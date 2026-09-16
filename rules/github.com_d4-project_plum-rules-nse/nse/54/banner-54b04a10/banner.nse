local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This is a robust banner scanner.
Connects to a TCP service, waits for a passive banner, sends two Enter
keystrokes if no data is received, and retries with a broken "GET /" if the service
closes the connection or remains silent. The received banner is stored in
host.registry and reported in the script output in all cases.

When a Telnet IAC byte (0xff) is received, the script performs minimal Telnet
negotiation, answers terminal-type requests with "dumb", preserves the raw
Telnet negotiation bytes in the output, and then appends the collected login
banner.
]]

author = "CIRCL/Paul JUNG (Thanat0s)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

---
-- @args smart-banner.wait Passive banner wait time in milliseconds.
--       Defaults to 500.
-- @args smart-banner.timeout Read timeout after sending data, in
--       milliseconds. Defaults to 2000.
-- @args smart-banner.maxbytes Maximum banner bytes to collect.
--       Defaults to 4096.
--       Telnet IAC bytes (0xff) trigger minimal negotiation. Raw negotiation
--       bytes are preserved before the readable login banner in output.
--
-- @usage
-- nmap -sV --script ./smart-banner.nse -p <ports> <target>
--
-- @output
-- |_ smart-banner: SSH-2.0-OpenSSH_9.2p1\x0A

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local SCRIPT_KEY = SCRIPT_NAME
local MAX_OUTPUT_CHARS = 255
local TELNET_IAC = string.char(255)
local TELNET_SE = 240
local TELNET_SB = 250
local TELNET_WILL = 251
local TELNET_WONT = 252
local TELNET_DO = 253
local TELNET_DONT = 254
local TELNET_OPT_SGA = 3
local TELNET_OPT_TTYPE = 24
local TELNET_TTYPE_IS = 0
local TELNET_TTYPE_SEND = 1
local read_available

local function get_arg(name, default)
  return tonumber(stdnse.get_script_args(SCRIPT_KEY .. "." .. name)) or default
end

local function is_close_error(err)
  if not err then
    return false
  end

  err = string.lower(tostring(err))
  return err:match("closed") or err:match("eof") or err:match("reset")
end

local function has_telnet_negotiation(data)
  if type(data) ~= "string" or data == "" then
    return false
  end

  for i = 1, #data do
    if data:byte(i) == 255 then
      return true
    end
  end

  return false
end

local function parse_telnet(data)
  local clean = {}
  local reply = {}
  local i = 1

  while i <= #data do
    local byte = data:byte(i)

    if byte ~= 255 then
      clean[#clean + 1] = data:sub(i, i)
      i = i + 1
    else
      local command = data:byte(i + 1)

      if not command then
        break
      elseif command == 255 then
        clean[#clean + 1] = TELNET_IAC
        i = i + 2
      elseif command == TELNET_WILL or command == TELNET_WONT or
          command == TELNET_DO or command == TELNET_DONT then
        local option = data:byte(i + 2)
        if not option then
          break
        end

        if command == TELNET_WILL and option == TELNET_OPT_SGA then
          reply[#reply + 1] = TELNET_IAC .. string.char(TELNET_DO, option)
        elseif command == TELNET_WILL then
          reply[#reply + 1] = TELNET_IAC .. string.char(TELNET_DONT, option)
        elseif command == TELNET_DO and option == TELNET_OPT_TTYPE then
          reply[#reply + 1] = TELNET_IAC .. string.char(TELNET_WILL, option)
        elseif command == TELNET_DO then
          reply[#reply + 1] = TELNET_IAC .. string.char(TELNET_WONT, option)
        end

        i = i + 3
      elseif command == TELNET_SB then
        local option = data:byte(i + 2)
        local request = data:byte(i + 3)
        if option == TELNET_OPT_TTYPE and request == TELNET_TTYPE_SEND then
          reply[#reply + 1] = TELNET_IAC .. string.char(TELNET_SB, TELNET_OPT_TTYPE,
            TELNET_TTYPE_IS) .. "dumb" .. TELNET_IAC .. string.char(TELNET_SE)
        end

        i = i + 2
        while i <= #data - 1 do
          if data:byte(i) == 255 and data:byte(i + 1) == TELNET_SE then
            i = i + 2
            break
          end
          i = i + 1
        end
      else
        i = i + 2
      end
    end
  end

  return table.concat(clean), table.concat(reply)
end

local function read_telnet_banner(socket, initial_data, read_timeout, max_bytes)
  local chunks = {}
  local prefix_chunks = {}
  local seen_text = false
  local total = 0
  local read_error
  local pending = initial_data

  for _ = 1, 8 do
    local clean, reply = parse_telnet(pending)

    if clean ~= "" then
      if not seen_text then
        local prefix = table.concat(prefix_chunks)
        if prefix ~= "" then
          if total + #prefix > max_bytes then
            prefix = prefix:sub(1, max_bytes - total)
          end
          chunks[#chunks + 1] = prefix
          total = total + #prefix
        end
        seen_text = true
      end

      if total + #clean > max_bytes then
        clean = clean:sub(1, max_bytes - total)
      end
      chunks[#chunks + 1] = clean
      total = total + #clean
    elseif not seen_text and pending ~= "" then
      prefix_chunks[#prefix_chunks + 1] = pending
    end

    if reply ~= "" then
      local status, send_error = socket:send(reply)
      if not status then
        return table.concat(chunks), send_error
      end
    end

    if total >= max_bytes then
      break
    end

    pending, read_error = read_available(socket, read_timeout, 250, max_bytes - total)
    if pending == "" then
      break
    end
  end

  if not seen_text and #prefix_chunks > 0 then
    return table.concat(prefix_chunks):sub(1, max_bytes), read_error
  end

  return table.concat(chunks), read_error
end

local function replace_nonprint(data, len)
  local output = {}
  local count = 0

  for char in data:gmatch(".") do
    local byte = char:byte()
    local token

    if byte < 32 or byte > 126 then
      token = string.format("\\x%02X", byte)
    else
      token = char
    end

    if type(len) == "number" and count + token:len() > len then
      return table.concat(output), true
    end

    output[#output + 1] = token
    count = count + token:len()
  end

  return table.concat(output), false
end

local function save_banner(host, port, result)
  host.registry[SCRIPT_KEY] = host.registry[SCRIPT_KEY] or {}
  host.registry[SCRIPT_KEY][port.number .. "/" .. port.protocol] = result
end

local function output_banner(out)
  if type(out) ~= "string" or out == "" then
    return nil
  end

  out = out:match("^%s*(.-)%s*$")

  local encoded, truncated = replace_nonprint(out, MAX_OUTPUT_CHARS)
  if truncated then
    encoded = replace_nonprint(out, MAX_OUTPUT_CHARS - 3) .. "..."
  end

  return encoded
end

local function connect_socket(host, port, timeout)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)

  local status, err = socket:connect(host.ip, port.number, port.protocol)
  if not status then
    socket:close()
    return nil, err
  end

  return socket
end

function read_available(socket, first_timeout, next_timeout, max_bytes)
  local chunks = {}
  local total = 0
  local last_error

  socket:set_timeout(first_timeout)

  while total < max_bytes do
    local status, data = socket:receive_bytes(1)
    if not status then
      last_error = data
      break
    end

    if not data or data == "" then
      break
    end

    if total + #data > max_bytes then
      data = data:sub(1, max_bytes - total)
    end

    table.insert(chunks, data)
    total = total + #data
    socket:set_timeout(next_timeout)
  end

  if #chunks > 0 then
    return table.concat(chunks), nil
  end

  return "", last_error
end

local function attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "connect",
      banner = "",
      closed = false,
      error = "connect failed: " .. (err or "unknown error")
    }
  end

  local banner, read_error = read_available(socket, wait_timeout, 250, max_bytes)
  if banner ~= "" then
    if has_telnet_negotiation(banner) then
      local clean_banner
      clean_banner, read_error = read_telnet_banner(socket, banner, read_timeout, max_bytes)
      socket:close()

      return {
        stage = "telnet",
        banner = clean_banner,
        closed = is_close_error(read_error),
        error = read_error
      }
    end

    socket:close()
    return {
      stage = "passive",
      banner = banner,
      closed = false
    }
  end

  if is_close_error(read_error) then
    socket:close()
    return {
      stage = "passive",
      banner = "",
      closed = true,
      error = read_error
    }
  end

  local status, send_error = socket:send("\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "enter",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "enter",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

local function attempt_get(host, port, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "get",
      banner = "",
      closed = false,
      error = "reconnect failed: " .. (err or "unknown error")
    }
  end

  local status, send_error = socket:send("GET /\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "get",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  local banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "get",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

action = function(host, port)
  local wait_timeout = get_arg("wait", 500)
  local read_timeout = get_arg("timeout", 2000)
  local max_bytes = get_arg("maxbytes", 4096)

  local result = attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  if result.stage ~= "telnet" and (result.closed or result.banner == "") then
    result = attempt_get(host, port, read_timeout, max_bytes)
  end

  save_banner(host, port, result)
  return output_banner(result.banner)
end
