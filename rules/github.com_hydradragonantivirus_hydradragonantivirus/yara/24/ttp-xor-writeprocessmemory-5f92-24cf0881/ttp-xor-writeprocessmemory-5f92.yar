rule TTP_XOR_WriteProcessMemory_5f92 {
  strings:
    $key_5f92 = { 08 e0 [2] 3a c2 [2] 3c f7 [2] 12 f7 [2] 2d eb }

  condition:
    any of them
}