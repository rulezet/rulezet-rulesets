rule TTP_XOR_WriteProcessMemory_4f92 {
  strings:
    $key_4f92 = { 18 e0 [2] 2a c2 [2] 2c f7 [2] 02 f7 [2] 3d eb }

  condition:
    any of them
}