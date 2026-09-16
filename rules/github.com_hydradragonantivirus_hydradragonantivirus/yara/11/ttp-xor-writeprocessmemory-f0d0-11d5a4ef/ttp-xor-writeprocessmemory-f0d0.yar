rule TTP_XOR_WriteProcessMemory_f0d0 {
  strings:
    $key_f0d0 = { a7 a2 [2] 95 80 [2] 93 b5 [2] bd b5 [2] 82 a9 }

  condition:
    any of them
}