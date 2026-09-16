rule TTP_XOR_WriteProcessMemory_63b1 {
  strings:
    $key_63b1 = { 34 c3 [2] 06 e1 [2] 00 d4 [2] 2e d4 [2] 11 c8 }

  condition:
    any of them
}