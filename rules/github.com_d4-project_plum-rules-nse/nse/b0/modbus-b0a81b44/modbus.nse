local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"

description = [[
Quick Modbus/TCP identification.
Sends a Read Device Identification request and extracts printable strings.
]]

author = "Plum"
license = "Same as Nmap"
categories = {"discovery", "safe"}

-- portrule = shortport.port_or_service(502, "modbus", "tcp")
portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 502
end
-- Read a 16-bit big endian integer from a string
local function read_uint16_be(data, index)
  local high_byte = data:byte(index) or 0
  local low_byte = data:byte(index + 1) or 0
  return high_byte * 256 + low_byte
end

-- Extract printable chunks from binary data
local function extract_printable_chunks(data)
  local chunks = {}

  -- Replace non-printable bytes with spaces
  data = data:gsub("[^\32-\126]", " ")

  -- Collect meaningful chunks
  for value in data:gmatch("%S[%S ]*") do
    value = value:gsub("^%s+", ""):gsub("%s+$", "")
    if #value >= 3 then
      table.insert(chunks, value)
    end
  end

  return table.concat(chunks, " ")
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local connect_status, connect_error = socket:connect(host, port)
  if not connect_status then
    return "connection failed: " .. (connect_error or "unknown error")
  end

  local request = string.char(
    0x00, 0x01, -- Transaction ID
    0x00, 0x00, -- Protocol ID
    0x00, 0x05, -- Length
    0x00,       -- Unit ID
    0x2B,       -- Function
    0x0E,       -- MEI Type
    0x01,       -- Read Device ID code
    0x00        -- Object ID
  )

  local send_status, send_error = socket:send(request)
  if not send_status then
    socket:close()
    return "send failed: " .. (send_error or "unknown error")
  end

  -- Important: receive_bytes(7) may return MORE than 7 bytes
  local receive_status, response = socket:receive_bytes(7)
  if not receive_status or not response or #response < 7 then
    socket:close()
    return "no valid response"
  end

  local header = response:sub(1, 7)
  local body = response:sub(8)

  -- MBAP length includes Unit ID, so body size is length - 1
  local expected_body_length = read_uint16_be(header, 5) - 1
  if expected_body_length <= 0 then
    socket:close()
    return "invalid response length"
  end

  -- If first read already included full body, do not read again
  local missing_bytes = expected_body_length - #body
  if missing_bytes > 0 then
    local body_status, more_body = socket:receive_bytes(missing_bytes)
    socket:close()

    if not body_status or not more_body then
      return "failed to read response body"
    end

    body = body .. more_body
  else
    socket:close()
    body = body:sub(1, expected_body_length)
  end

  local identification = extract_printable_chunks(body)
  if identification == "" then
    return "no printable modbus identification found"
  end

  return identification
end