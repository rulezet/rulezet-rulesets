rule TTP_XOR_WriteProcessMemory_5e4d {
  strings:
    $key_5e4d = { 09 3f [2] 3b 1d [2] 3d 28 [2] 13 28 [2] 2c 34 }

  condition:
    any of them
}