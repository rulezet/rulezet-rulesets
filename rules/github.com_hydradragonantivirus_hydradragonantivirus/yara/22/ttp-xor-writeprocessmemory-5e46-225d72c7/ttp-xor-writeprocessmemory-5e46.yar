rule TTP_XOR_WriteProcessMemory_5e46 {
  strings:
    $key_5e46 = { 09 34 [2] 3b 16 [2] 3d 23 [2] 13 23 [2] 2c 3f }

  condition:
    any of them
}