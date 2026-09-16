rule TTP_XOR_WriteProcessMemory_f09c {
  strings:
    $key_f09c = { a7 ee [2] 95 cc [2] 93 f9 [2] bd f9 [2] 82 e5 }

  condition:
    any of them
}