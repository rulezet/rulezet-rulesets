rule TTP_XOR_WriteProcessMemory_71f6 {
  strings:
    $key_71f6 = { 26 84 [2] 14 a6 [2] 12 93 [2] 3c 93 [2] 03 8f }

  condition:
    any of them
}