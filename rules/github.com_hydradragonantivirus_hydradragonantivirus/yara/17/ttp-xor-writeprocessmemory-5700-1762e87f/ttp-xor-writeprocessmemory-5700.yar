rule TTP_XOR_WriteProcessMemory_5700 {
  strings:
    $key_5700 = { 00 72 [2] 32 50 [2] 34 65 [2] 1a 65 [2] 25 79 }

  condition:
    any of them
}