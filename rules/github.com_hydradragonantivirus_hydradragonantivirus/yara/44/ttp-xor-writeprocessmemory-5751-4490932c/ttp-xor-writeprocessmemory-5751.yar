rule TTP_XOR_WriteProcessMemory_5751 {
  strings:
    $key_5751 = { 00 23 [2] 32 01 [2] 34 34 [2] 1a 34 [2] 25 28 }

  condition:
    any of them
}