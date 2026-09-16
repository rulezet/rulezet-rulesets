rule TTP_XOR_WriteProcessMemory_5e71 {
  strings:
    $key_5e71 = { 09 03 [2] 3b 21 [2] 3d 14 [2] 13 14 [2] 2c 08 }

  condition:
    any of them
}