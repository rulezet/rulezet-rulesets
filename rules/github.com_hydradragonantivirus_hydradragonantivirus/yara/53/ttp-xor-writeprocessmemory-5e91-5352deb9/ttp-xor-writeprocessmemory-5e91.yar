rule TTP_XOR_WriteProcessMemory_5e91 {
  strings:
    $key_5e91 = { 09 e3 [2] 3b c1 [2] 3d f4 [2] 13 f4 [2] 2c e8 }

  condition:
    any of them
}