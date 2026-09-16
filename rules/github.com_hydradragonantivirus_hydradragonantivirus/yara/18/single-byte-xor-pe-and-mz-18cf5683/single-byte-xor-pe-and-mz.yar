rule single_byte_xor_pe_and_mz {
  meta:
    author      = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte xor of a PE starting at offset 0"

  strings:
    $b = "PE\x00\x00" xor(0x01-0xff)

  condition:
    $b at uint32(0x3c) ^ (uint32(@b[1]) ^ 0x00004550) and
    (uint16(0x00) ^ (uint16(@b[1]) ^ 0x4550)) == 0x5a4d
}