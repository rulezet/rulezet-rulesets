rule TTP_XOR_WriteProcessMemory_feb1 {
  strings:
    $key_feb1 = { a9 c3 [2] 9b e1 [2] 9d d4 [2] b3 d4 [2] 8c c8 }

  condition:
    any of them
}