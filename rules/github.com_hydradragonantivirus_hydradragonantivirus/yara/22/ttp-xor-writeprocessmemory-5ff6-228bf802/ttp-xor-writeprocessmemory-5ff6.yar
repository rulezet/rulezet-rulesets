rule TTP_XOR_WriteProcessMemory_5ff6 {
  strings:
    $key_5ff6 = { 08 84 [2] 3a a6 [2] 3c 93 [2] 12 93 [2] 2d 8f }

  condition:
    any of them
}