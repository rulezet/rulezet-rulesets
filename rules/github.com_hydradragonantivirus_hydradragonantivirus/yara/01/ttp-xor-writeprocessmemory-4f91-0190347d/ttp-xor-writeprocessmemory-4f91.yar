rule TTP_XOR_WriteProcessMemory_4f91 {
  strings:
    $key_4f91 = { 18 e3 [2] 2a c1 [2] 2c f4 [2] 02 f4 [2] 3d e8 }

  condition:
    any of them
}