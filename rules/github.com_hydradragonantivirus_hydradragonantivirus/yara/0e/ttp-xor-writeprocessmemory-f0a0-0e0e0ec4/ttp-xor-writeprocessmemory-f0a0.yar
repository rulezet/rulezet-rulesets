rule TTP_XOR_WriteProcessMemory_f0a0 {
  strings:
    $key_f0a0 = { a7 d2 [2] 95 f0 [2] 93 c5 [2] bd c5 [2] 82 d9 }

  condition:
    any of them
}