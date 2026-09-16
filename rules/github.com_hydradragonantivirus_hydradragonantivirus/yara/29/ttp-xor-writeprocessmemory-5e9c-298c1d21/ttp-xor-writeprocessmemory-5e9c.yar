rule TTP_XOR_WriteProcessMemory_5e9c {
  strings:
    $key_5e9c = { 09 ee [2] 3b cc [2] 3d f9 [2] 13 f9 [2] 2c e5 }

  condition:
    any of them
}