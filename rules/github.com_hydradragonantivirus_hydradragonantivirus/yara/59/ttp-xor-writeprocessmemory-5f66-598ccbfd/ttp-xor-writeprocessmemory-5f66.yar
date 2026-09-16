rule TTP_XOR_WriteProcessMemory_5f66 {
  strings:
    $key_5f66 = { 08 14 [2] 3a 36 [2] 3c 03 [2] 12 03 [2] 2d 1f }

  condition:
    any of them
}