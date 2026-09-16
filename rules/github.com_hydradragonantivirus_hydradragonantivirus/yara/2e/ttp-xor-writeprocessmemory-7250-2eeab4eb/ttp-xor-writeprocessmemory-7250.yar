rule TTP_XOR_WriteProcessMemory_7250 {
  strings:
    $key_7250 = { 25 22 [2] 17 00 [2] 11 35 [2] 3f 35 [2] 00 29 }

  condition:
    any of them
}