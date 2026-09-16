rule TTP_XOR_WriteProcessMemory_f7c0 {
  strings:
    $key_f7c0 = { a0 b2 [2] 92 90 [2] 94 a5 [2] ba a5 [2] 85 b9 }

  condition:
    any of them
}