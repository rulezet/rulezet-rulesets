rule TTP_XOR_WriteProcessMemory_7750 {
  strings:
    $key_7750 = { 20 22 [2] 12 00 [2] 14 35 [2] 3a 35 [2] 05 29 }

  condition:
    any of them
}