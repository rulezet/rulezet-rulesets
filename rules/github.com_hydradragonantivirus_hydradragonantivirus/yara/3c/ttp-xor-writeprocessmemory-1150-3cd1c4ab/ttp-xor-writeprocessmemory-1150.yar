rule TTP_XOR_WriteProcessMemory_1150 {
  strings:
    $key_1150 = { 46 22 [2] 74 00 [2] 72 35 [2] 5c 35 [2] 63 29 }

  condition:
    any of them
}