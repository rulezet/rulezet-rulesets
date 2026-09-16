rule TTP_XOR_WriteProcessMemory_5350 {
  strings:
    $key_5350 = { 04 22 [2] 36 00 [2] 30 35 [2] 1e 35 [2] 21 29 }

  condition:
    any of them
}