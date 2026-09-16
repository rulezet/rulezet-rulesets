rule TTP_XOR_WriteProcessMemory_5749 {
  strings:
    $key_5749 = { 00 3b [2] 32 19 [2] 34 2c [2] 1a 2c [2] 25 30 }

  condition:
    any of them
}