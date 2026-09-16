rule TTP_XOR_WriteProcessMemory_5f50 {
  strings:
    $key_5f50 = { 08 22 [2] 3a 00 [2] 3c 35 [2] 12 35 [2] 2d 29 }

  condition:
    any of them
}