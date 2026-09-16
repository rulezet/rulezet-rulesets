rule TTP_XOR_WriteProcessMemory_f0d9 {
  strings:
    $key_f0d9 = { a7 ab [2] 95 89 [2] 93 bc [2] bd bc [2] 82 a0 }

  condition:
    any of them
}