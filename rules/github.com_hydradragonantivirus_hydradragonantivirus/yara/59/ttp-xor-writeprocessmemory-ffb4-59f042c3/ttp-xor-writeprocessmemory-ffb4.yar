rule TTP_XOR_WriteProcessMemory_ffb4 {
  strings:
    $key_ffb4 = { a8 c6 [2] 9a e4 [2] 9c d1 [2] b2 d1 [2] 8d cd }

  condition:
    any of them
}