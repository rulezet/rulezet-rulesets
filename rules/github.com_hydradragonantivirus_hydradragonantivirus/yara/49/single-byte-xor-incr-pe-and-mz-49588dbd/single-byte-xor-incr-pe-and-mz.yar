rule single_byte_xor_incr_pe_and_mz {
  meta:
    author      = "Wesley Shields <wxs@atarininja.org>"
    description = "Look for single byte incrementing xor of a PE starting at offset 0"

  condition:
    uint16(0) != 0x5a4d and
    uint8(0) ^ 0x4d == ((uint8(1) ^ 0x5a) - 1) & 0xff and
    uint32(
      uint32(0x3c) ^ (
        (uint8(0) ^ 0x4d) + 0x3c & 0xff |
        ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
        ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
        ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
      )
    ) ^ (
      (uint8(0) ^ 0x4d) + (
        uint32(0x3c) ^ (
          (uint8(0) ^ 0x4d) + 0x3c & 0xff |
          ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
          ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
          ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
        )
      ) & 0xff |
      ((
          (uint8(0) ^ 0x4d) + (
            uint32(0x3c) ^ (
              (uint8(0) ^ 0x4d) + 0x3c & 0xff |
              ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
              ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
              ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
            )
          ) + 1
        ) & 0xff) << 8 |
      ((
          (uint8(0) ^ 0x4d) + (
            uint32(0x3c) ^ (
              (uint8(0) ^ 0x4d) + 0x3c & 0xff |
              ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
              ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
              ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
            )
          ) + 2
        ) & 0xff) << 16 |
      ((
          (uint8(0) ^ 0x4d) + (
            uint32(0x3c) ^ (
              (uint8(0) ^ 0x4d) + 0x3c |
              ((uint8(0) ^ 0x4d) + 0x3d & 0xff) << 8 |
              ((uint8(0) ^ 0x4d) + 0x3e & 0xff) << 16 |
              ((uint8(0) ^ 0x4d) + 0x3f & 0xff) << 24
            )
          ) + 3
        ) & 0xff) << 24
    ) == 0x00004550
}