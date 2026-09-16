rule TTP_XOR_WriteProcessMemory_f781 {
  strings:
    $key_f781 = { a0 f3 [2] 92 d1 [2] 94 e4 [2] ba e4 [2] 85 f8 }

  condition:
    any of them
}