rule TTP_XOR_WriteProcessMemory_1750 {
  strings:
    $key_1750 = { 40 22 [2] 72 00 [2] 74 35 [2] 5a 35 [2] 65 29 }

  condition:
    any of them
}