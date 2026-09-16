rule TTP_XOR_WriteProcessMemory_5f46 {
  strings:
    $key_5f46 = { 08 34 [2] 3a 16 [2] 3c 23 [2] 12 23 [2] 2d 3f }

  condition:
    any of them
}