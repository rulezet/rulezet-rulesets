rule TTP_XOR_WriteProcessMemory_5f16 {
  strings:
    $key_5f16 = { 08 64 [2] 3a 46 [2] 3c 73 [2] 12 73 [2] 2d 6f }

  condition:
    any of them
}