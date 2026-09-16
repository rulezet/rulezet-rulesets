rule TTP_XOR_WriteProcessMemory_5761 {
  strings:
    $key_5761 = { 00 13 [2] 32 31 [2] 34 04 [2] 1a 04 [2] 25 18 }

  condition:
    any of them
}