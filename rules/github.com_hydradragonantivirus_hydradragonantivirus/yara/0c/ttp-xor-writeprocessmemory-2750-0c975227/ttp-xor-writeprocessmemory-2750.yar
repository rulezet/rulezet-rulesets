rule TTP_XOR_WriteProcessMemory_2750 {
  strings:
    $key_2750 = { 70 22 [2] 42 00 [2] 44 35 [2] 6a 35 [2] 55 29 }

  condition:
    any of them
}