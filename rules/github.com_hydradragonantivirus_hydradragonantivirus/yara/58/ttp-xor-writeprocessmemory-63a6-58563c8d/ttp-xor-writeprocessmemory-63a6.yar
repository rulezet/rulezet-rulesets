rule TTP_XOR_WriteProcessMemory_63a6 {
  strings:
    $key_63a6 = { 34 d4 [2] 06 f6 [2] 00 c3 [2] 2e c3 [2] 11 df }

  condition:
    any of them
}