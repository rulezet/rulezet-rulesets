rule TTP_XOR_WriteProcessMemory_5e48 {
  strings:
    $key_5e48 = { 09 3a [2] 3b 18 [2] 3d 2d [2] 13 2d [2] 2c 31 }

  condition:
    any of them
}