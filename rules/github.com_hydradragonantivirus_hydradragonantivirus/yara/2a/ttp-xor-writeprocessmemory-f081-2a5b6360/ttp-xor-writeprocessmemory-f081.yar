rule TTP_XOR_WriteProcessMemory_f081 {
  strings:
    $key_f081 = { a7 f3 [2] 95 d1 [2] 93 e4 [2] bd e4 [2] 82 f8 }

  condition:
    any of them
}