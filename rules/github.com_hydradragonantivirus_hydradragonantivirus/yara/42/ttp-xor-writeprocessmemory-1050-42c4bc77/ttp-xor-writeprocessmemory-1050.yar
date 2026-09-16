rule TTP_XOR_WriteProcessMemory_1050 {
  strings:
    $key_1050 = { 47 22 [2] 75 00 [2] 73 35 [2] 5d 35 [2] 62 29 }

  condition:
    any of them
}