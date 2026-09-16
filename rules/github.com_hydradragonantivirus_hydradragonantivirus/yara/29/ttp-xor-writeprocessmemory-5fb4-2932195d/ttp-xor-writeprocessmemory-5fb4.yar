rule TTP_XOR_WriteProcessMemory_5fb4 {
  strings:
    $key_5fb4 = { 08 c6 [2] 3a e4 [2] 3c d1 [2] 12 d1 [2] 2d cd }

  condition:
    any of them
}