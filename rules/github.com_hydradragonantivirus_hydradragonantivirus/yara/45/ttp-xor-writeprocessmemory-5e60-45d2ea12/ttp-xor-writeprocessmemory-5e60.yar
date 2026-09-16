rule TTP_XOR_WriteProcessMemory_5e60 {
  strings:
    $key_5e60 = { 09 12 [2] 3b 30 [2] 3d 05 [2] 13 05 [2] 2c 19 }

  condition:
    any of them
}