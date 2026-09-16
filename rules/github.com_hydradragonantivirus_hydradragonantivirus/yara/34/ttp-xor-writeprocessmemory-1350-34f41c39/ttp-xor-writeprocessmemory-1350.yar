rule TTP_XOR_WriteProcessMemory_1350 {
  strings:
    $key_1350 = { 44 22 [2] 76 00 [2] 70 35 [2] 5e 35 [2] 61 29 }

  condition:
    any of them
}