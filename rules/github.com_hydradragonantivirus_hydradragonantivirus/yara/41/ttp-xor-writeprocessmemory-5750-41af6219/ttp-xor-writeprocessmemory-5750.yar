rule TTP_XOR_WriteProcessMemory_5750 {
  strings:
    $key_5750 = { 00 22 [2] 32 00 [2] 34 35 [2] 1a 35 [2] 25 29 }

  condition:
    any of them
}