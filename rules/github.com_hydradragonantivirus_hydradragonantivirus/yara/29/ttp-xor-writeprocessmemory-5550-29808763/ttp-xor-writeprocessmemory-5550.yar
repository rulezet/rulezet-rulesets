rule TTP_XOR_WriteProcessMemory_5550 {
  strings:
    $key_5550 = { 02 22 [2] 30 00 [2] 36 35 [2] 18 35 [2] 27 29 }

  condition:
    any of them
}