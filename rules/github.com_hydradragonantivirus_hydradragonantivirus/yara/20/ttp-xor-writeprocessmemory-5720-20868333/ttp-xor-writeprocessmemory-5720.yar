rule TTP_XOR_WriteProcessMemory_5720 {
  strings:
    $key_5720 = { 00 52 [2] 32 70 [2] 34 45 [2] 1a 45 [2] 25 59 }

  condition:
    any of them
}