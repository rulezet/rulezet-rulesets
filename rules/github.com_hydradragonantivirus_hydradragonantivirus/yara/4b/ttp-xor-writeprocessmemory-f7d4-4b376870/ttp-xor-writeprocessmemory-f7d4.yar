rule TTP_XOR_WriteProcessMemory_f7d4 {
  strings:
    $key_f7d4 = { a0 a6 [2] 92 84 [2] 94 b1 [2] ba b1 [2] 85 ad }

  condition:
    any of them
}