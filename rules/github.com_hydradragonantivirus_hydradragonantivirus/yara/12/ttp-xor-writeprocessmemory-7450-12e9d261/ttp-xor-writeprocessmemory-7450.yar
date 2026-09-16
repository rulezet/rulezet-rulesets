rule TTP_XOR_WriteProcessMemory_7450 {
  strings:
    $key_7450 = { 23 22 [2] 11 00 [2] 17 35 [2] 39 35 [2] 06 29 }

  condition:
    any of them
}