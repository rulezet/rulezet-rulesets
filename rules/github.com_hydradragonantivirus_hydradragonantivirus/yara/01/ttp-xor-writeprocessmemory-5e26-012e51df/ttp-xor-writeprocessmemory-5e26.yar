rule TTP_XOR_WriteProcessMemory_5e26 {
  strings:
    $key_5e26 = { 09 54 [2] 3b 76 [2] 3d 43 [2] 13 43 [2] 2c 5f }

  condition:
    any of them
}