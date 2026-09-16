rule TTP_XOR_WriteProcessMemory_5e73 {
  strings:
    $key_5e73 = { 09 01 [2] 3b 23 [2] 3d 16 [2] 13 16 [2] 2c 0a }

  condition:
    any of them
}