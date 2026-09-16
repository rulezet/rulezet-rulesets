rule TTP_XOR_WriteProcessMemory_4450 {
  strings:
    $key_4450 = { 13 22 [2] 21 00 [2] 27 35 [2] 09 35 [2] 36 29 }

  condition:
    any of them
}