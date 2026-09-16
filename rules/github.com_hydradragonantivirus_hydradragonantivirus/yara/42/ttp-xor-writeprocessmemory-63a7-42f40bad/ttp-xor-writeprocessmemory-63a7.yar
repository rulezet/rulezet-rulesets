rule TTP_XOR_WriteProcessMemory_63a7 {
  strings:
    $key_63a7 = { 34 d5 [2] 06 f7 [2] 00 c2 [2] 2e c2 [2] 11 de }

  condition:
    any of them
}