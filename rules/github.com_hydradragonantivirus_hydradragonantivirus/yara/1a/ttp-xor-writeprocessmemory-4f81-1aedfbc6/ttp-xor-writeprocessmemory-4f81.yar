rule TTP_XOR_WriteProcessMemory_4f81 {
  strings:
    $key_4f81 = { 18 f3 [2] 2a d1 [2] 2c e4 [2] 02 e4 [2] 3d f8 }

  condition:
    any of them
}