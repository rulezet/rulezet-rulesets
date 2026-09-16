local nmap = require "nmap"
local stdnse = require "stdnse"
local openssl = require "openssl"

description = [[
Active JA4S-like TLS server fingerprint.

This script sends a TLS ClientHello, parses ServerHello, and builds a JA4S-like value.
]]

author = "custom"
license = "Same as Nmap"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp"
    and port.state == "open"
    and (
      port.number == 443
      or port.number == 8443
      or port.number == 9443
      or port.service == "https"
      or port.service == "ssl"
    )
end

local function uint16(data, offset)
  local first_byte, second_byte = data:byte(offset, offset + 1)

  if not first_byte or not second_byte then
    return nil
  end

  return first_byte * 256 + second_byte
end

local function uint24(data, offset)
  local first_byte, second_byte, third_byte = data:byte(offset, offset + 2)

  if not first_byte or not second_byte or not third_byte then
    return nil
  end

  return first_byte * 65536 + second_byte * 256 + third_byte
end

local function hex16(value)
  return string.format("%04x", value)
end

local function sha256_12(value)
  local digest = openssl.digest("sha256", value)
  return stdnse.tohex(digest):sub(1, 12)
end

local function tls_version_code(version)
  local version_codes = {
    [0x0300] = "10",
    [0x0301] = "10",
    [0x0302] = "11",
    [0x0303] = "12",
    [0x0304] = "13",
  }

  return version_codes[version] or "00"
end


local function build_client_hello(hostname)
  local random_bytes = string.rep("\x42", 32)

  -- TLS 1.2 compatible cipher suites only
  local cipher_suites =
    "\xc0\x2c" .. -- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    "\xc0\x2b" .. -- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    "\xc0\x30" .. -- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    "\xc0\x2f" .. -- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    "\xcc\xa9" .. -- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    "\xcc\xa8" .. -- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    "\xc0\x24" .. -- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    "\xc0\x23" .. -- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    "\xc0\x28" .. -- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    "\xc0\x27" .. -- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    "\xc0\x0a" .. -- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    "\xc0\x09" .. -- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    "\xc0\x14" .. -- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    "\xc0\x13" .. -- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    "\x00\x9d" .. -- TLS_RSA_WITH_AES_256_GCM_SHA384
    "\x00\x9c" .. -- TLS_RSA_WITH_AES_128_GCM_SHA256
    "\x00\x35" .. -- TLS_RSA_WITH_AES_256_CBC_SHA
    "\x00\x2f" .. -- TLS_RSA_WITH_AES_128_CBC_SHA
    "\x00\xff"    -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV

  local compression_methods = "\x01\x00"
  local extensions = ""

  -- SNI
  if hostname and hostname ~= "" then
    local server_name_entry =
      "\x00" ..
      string.pack(">I2", #hostname) ..
      hostname

    local server_name_list =
      string.pack(">I2", #server_name_entry) ..
      server_name_entry

    extensions =
      extensions ..
      "\x00\x00" ..
      string.pack(">I2", #server_name_list) ..
      server_name_list
  end

  -- Supported Groups
  local supported_groups =
    "\x00\x08" ..
    "\x00\x1d" ..
    "\x00\x17" ..
    "\x00\x18" ..
    "\x00\x19"

  extensions =
    extensions ..
    "\x00\x0a" ..
    string.pack(">I2", #supported_groups) ..
    supported_groups

  -- EC Point Formats
  local ec_point_formats = "\x01\x00"

  extensions =
    extensions ..
    "\x00\x0b" ..
    string.pack(">I2", #ec_point_formats) ..
    ec_point_formats

  -- Signature Algorithms
  local signature_algorithms =
    "\x00\x12" ..
    "\x04\x03" ..
    "\x08\x04" ..
    "\x04\x01" ..
    "\x05\x03" ..
    "\x08\x05" ..
    "\x05\x01" ..
    "\x06\x03" ..
    "\x06\x01" ..
    "\x02\x01"

  extensions =
    extensions ..
    "\x00\x0d" ..
    string.pack(">I2", #signature_algorithms) ..
    signature_algorithms

  -- ALPN
  local alpn_protocols =
    "\x02h2" ..
    "\x08http/1.1"

  local alpn =
    string.pack(">I2", #alpn_protocols) ..
    alpn_protocols

  extensions =
    extensions ..
    "\x00\x10" ..
    string.pack(">I2", #alpn) ..
    alpn

  -- Encrypt-then-MAC
  extensions = extensions .. "\x00\x16\x00\x00"

  -- Extended Master Secret
  extensions = extensions .. "\x00\x17\x00\x00"

  -- Renegotiation Info
  extensions = extensions .. "\xff\x01\x00\x01\x00"

  local extensions_block =
    string.pack(">I2", #extensions) ..
    extensions

  local client_hello_body =
    "\x03\x03" ..
    random_bytes ..
    "\x00" ..
    string.pack(">I2", #cipher_suites) ..
    cipher_suites ..
    compression_methods ..
    extensions_block

  local handshake =
    "\x01" ..
    string.pack(">I3", #client_hello_body) ..
    client_hello_body

  local record =
    "\x16\x03\x01" ..
    string.pack(">I2", #handshake) ..
    handshake

  return record
end

local function parse_server_hello(data)
  local offset = 1

  while offset + 5 <= #data do
    local record_type = data:byte(offset)
    local record_length = uint16(data, offset + 3)

    if not record_length then
      return nil
    end

    local record_body_offset = offset + 5
    local record_body_end = record_body_offset + record_length - 1

    if #data < record_body_end then
      return nil
    end

    if record_type == 22 then
      local handshake_type = data:byte(record_body_offset)

      if handshake_type == 2 then
        local handshake_length = uint24(data, record_body_offset + 1)
        local position = record_body_offset + 4

        local legacy_version = uint16(data, position)
        position = position + 2 + 32

        local session_id_length = data:byte(position)
        position = position + 1 + session_id_length

        local cipher_suite = uint16(data, position)
        position = position + 2

        -- Compression method
        position = position + 1

        local selected_version = legacy_version
        local selected_alpn = "00"
        local extension_ids = {}

        if position + 2 <= record_body_offset + 4 + handshake_length then
          local extensions_length = uint16(data, position)
          position = position + 2

          local extensions_end = position + extensions_length - 1

          while position + 4 <= extensions_end do
            local extension_type = uint16(data, position)
            local extension_length = uint16(data, position + 2)
            local extension_data_offset = position + 4

            table.insert(extension_ids, hex16(extension_type))

            -- ALPN
            if extension_type == 16 and extension_length >= 3 then
              local alpn_length = data:byte(extension_data_offset + 2)
              local alpn_value = data:sub(
                extension_data_offset + 3,
                extension_data_offset + 2 + alpn_length
              )

              selected_alpn = alpn_value:gsub("[^%w]", "")
            end

            -- Supported Versions
            if extension_type == 43 and extension_length == 2 then
              selected_version = uint16(data, extension_data_offset)
            end

            position = extension_data_offset + extension_length
          end
        end

        table.sort(extension_ids)

        return {
          version = selected_version,
          cipher_suite = cipher_suite,
          selected_alpn = selected_alpn,
          extension_ids = extension_ids,
        }
      end
    end

    offset = record_body_end + 1
  end

  return nil
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local connect_status = socket:connect(host.ip, port.number, port.protocol)

  if not connect_status then
    socket:close()
    return nil
  end

  local hostname =
    stdnse.get_script_args("tls.servername")
    or host.targetname
    or host.name

  socket:send(build_client_hello(hostname))

  local response = ""

  for _ = 1, 20 do
    local receive_status, chunk = socket:receive_bytes(1)

    if not receive_status or not chunk then
      break
    end

    response = response .. chunk

    local parsed = parse_server_hello(response)

    if parsed then
      socket:close()

      local version_part = tls_version_code(parsed.version)
      local extension_count = string.format("%02d", #parsed.extension_ids)
      local cipher_part = hex16(parsed.cipher_suite)
      local extension_hash = sha256_12(table.concat(parsed.extension_ids, ","))

      local ja4s_like = string.format(
        "t%s%s%s_%s_%s",
        version_part,
        extension_count,
        parsed.selected_alpn,
        cipher_part,
        extension_hash
      )

      return {
        ja4s_like = ja4s_like,
        tls_version = string.format("0x%04x", parsed.version),
        cipher_suite = cipher_part,
        extensions = table.concat(parsed.extension_ids, ","),
      }
    end
  end

  socket:close()

  if response:sub(1, 1) == "\x15" then
    local alert_level = response:byte(6) or 0
    local alert_description = response:byte(7) or 0

    return string.format(
      "TLS alert received: level=%d description=%d",
      alert_level,
      alert_description
    )
  end

  return "No ServerHello received"
end