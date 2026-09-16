rule TTP_XOR_WriteProcessMemory_5e50 {
  strings:
    $key_5e50 = { 09 22 [2] 3b 00 [2] 3d 35 [2] 13 35 [2] 2c 29 }

  condition:
    any of them
}