rule TTP_XOR_WriteProcessMemory_f0d2 {
  strings:
    $key_f0d2 = { a7 a0 [2] 95 82 [2] 93 b7 [2] bd b7 [2] 82 ab }

  condition:
    any of them
}