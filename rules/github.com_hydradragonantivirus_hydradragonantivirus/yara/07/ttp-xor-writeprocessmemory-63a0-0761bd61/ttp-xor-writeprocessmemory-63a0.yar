rule TTP_XOR_WriteProcessMemory_63a0 {
  strings:
    $key_63a0 = { 34 d2 [2] 06 f0 [2] 00 c5 [2] 2e c5 [2] 11 d9 }

  condition:
    any of them
}