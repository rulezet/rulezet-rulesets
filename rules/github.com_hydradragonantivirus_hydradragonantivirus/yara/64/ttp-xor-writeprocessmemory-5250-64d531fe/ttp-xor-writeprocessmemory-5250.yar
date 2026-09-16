rule TTP_XOR_WriteProcessMemory_5250 {
  strings:
    $key_5250 = { 05 22 [2] 37 00 [2] 31 35 [2] 1f 35 [2] 20 29 }

  condition:
    any of them
}