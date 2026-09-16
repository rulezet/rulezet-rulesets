rule TTP_XOR_WriteProcessMemory_1fb4 {
  strings:
    $key_1fb4 = { 48 c6 [2] 7a e4 [2] 7c d1 [2] 52 d1 [2] 6d cd }

  condition:
    any of them
}