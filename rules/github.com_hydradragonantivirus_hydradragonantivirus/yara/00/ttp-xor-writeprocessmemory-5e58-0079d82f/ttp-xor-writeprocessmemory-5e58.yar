rule TTP_XOR_WriteProcessMemory_5e58 {
  strings:
    $key_5e58 = { 09 2a [2] 3b 08 [2] 3d 3d [2] 13 3d [2] 2c 21 }

  condition:
    any of them
}