rule TTP_XOR_WriteProcessMemory_4750 {
  strings:
    $key_4750 = { 10 22 [2] 22 00 [2] 24 35 [2] 0a 35 [2] 35 29 }

  condition:
    any of them
}