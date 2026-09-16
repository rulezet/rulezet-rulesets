rule TTP_XOR_WriteProcessMemory_f090 {
  strings:
    $key_f090 = { a7 e2 [2] 95 c0 [2] 93 f5 [2] bd f5 [2] 82 e9 }

  condition:
    any of them
}