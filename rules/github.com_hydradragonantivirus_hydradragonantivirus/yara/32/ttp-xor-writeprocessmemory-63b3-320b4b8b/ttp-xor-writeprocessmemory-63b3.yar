rule TTP_XOR_WriteProcessMemory_63b3 {
  strings:
    $key_63b3 = { 34 c1 [2] 06 e3 [2] 00 d6 [2] 2e d6 [2] 11 ca }

  condition:
    any of them
}