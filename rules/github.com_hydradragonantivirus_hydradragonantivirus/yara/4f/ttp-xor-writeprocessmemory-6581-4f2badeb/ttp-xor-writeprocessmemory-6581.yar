rule TTP_XOR_WriteProcessMemory_6581 {
  strings:
    $key_6581 = { 32 f3 [2] 00 d1 [2] 06 e4 [2] 28 e4 [2] 17 f8 }

  condition:
    any of them
}