rule TTP_XOR_WriteProcessMemory_63b0 {
  strings:
    $key_63b0 = { 34 c2 [2] 06 e0 [2] 00 d5 [2] 2e d5 [2] 11 c9 }

  condition:
    any of them
}