rule TTP_XOR_WriteProcessMemory_5760 {
  strings:
    $key_5760 = { 00 12 [2] 32 30 [2] 34 05 [2] 1a 05 [2] 25 19 }

  condition:
    any of them
}