rule TTP_XOR_WriteProcessMemory_5e00 {
  strings:
    $key_5e00 = { 09 72 [2] 3b 50 [2] 3d 65 [2] 13 65 [2] 2c 79 }

  condition:
    any of them
}