rule TTP_XOR_WriteProcessMemory_63b4 {
  strings:
    $key_63b4 = { 34 c6 [2] 06 e4 [2] 00 d1 [2] 2e d1 [2] 11 cd }

  condition:
    any of them
}