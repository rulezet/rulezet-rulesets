rule TTP_XOR_WriteProcessMemory_5f91 {
  strings:
    $key_5f91 = { 08 e3 [2] 3a c1 [2] 3c f4 [2] 12 f4 [2] 2d e8 }

  condition:
    any of them
}