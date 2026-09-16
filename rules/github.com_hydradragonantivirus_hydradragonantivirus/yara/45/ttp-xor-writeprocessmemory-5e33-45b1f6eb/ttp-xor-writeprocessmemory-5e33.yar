rule TTP_XOR_WriteProcessMemory_5e33 {
  strings:
    $key_5e33 = { 09 41 [2] 3b 63 [2] 3d 56 [2] 13 56 [2] 2c 4a }

  condition:
    any of them
}