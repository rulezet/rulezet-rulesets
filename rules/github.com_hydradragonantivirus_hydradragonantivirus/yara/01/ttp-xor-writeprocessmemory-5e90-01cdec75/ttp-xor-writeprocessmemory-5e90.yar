rule TTP_XOR_WriteProcessMemory_5e90 {
  strings:
    $key_5e90 = { 09 e2 [2] 3b c0 [2] 3d f5 [2] 13 f5 [2] 2c e9 }

  condition:
    any of them
}