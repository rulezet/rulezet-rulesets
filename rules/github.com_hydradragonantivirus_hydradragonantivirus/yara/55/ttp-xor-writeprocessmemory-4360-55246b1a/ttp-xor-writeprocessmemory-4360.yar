rule TTP_XOR_WriteProcessMemory_4360 {
  strings:
    $key_4360 = { 14 12 [2] 26 30 [2] 20 05 [2] 0e 05 [2] 31 19 }

  condition:
    any of them
}