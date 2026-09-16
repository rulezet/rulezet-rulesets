rule TTP_XOR_WriteProcessMemory_f7a0 {
  strings:
    $key_f7a0 = { a0 d2 [2] 92 f0 [2] 94 c5 [2] ba c5 [2] 85 d9 }

  condition:
    any of them
}