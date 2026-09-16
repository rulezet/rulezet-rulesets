rule TTP_XOR_WriteProcessMemory_57a7 {
  strings:
    $key_57a7 = { 00 d5 [2] 32 f7 [2] 34 c2 [2] 1a c2 [2] 25 de }

  condition:
    any of them
}