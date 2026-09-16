rule TTP_XOR_WriteProcessMemory_5050 {
  strings:
    $key_5050 = { 07 22 [2] 35 00 [2] 33 35 [2] 1d 35 [2] 22 29 }

  condition:
    any of them
}