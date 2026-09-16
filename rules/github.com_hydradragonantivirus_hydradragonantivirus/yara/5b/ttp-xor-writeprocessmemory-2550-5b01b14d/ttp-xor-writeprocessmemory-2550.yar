rule TTP_XOR_WriteProcessMemory_2550 {
  strings:
    $key_2550 = { 72 22 [2] 40 00 [2] 46 35 [2] 68 35 [2] 57 29 }

  condition:
    any of them
}