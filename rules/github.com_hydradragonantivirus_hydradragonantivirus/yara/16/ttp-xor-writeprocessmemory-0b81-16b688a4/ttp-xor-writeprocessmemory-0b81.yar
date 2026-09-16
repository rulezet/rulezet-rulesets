rule TTP_XOR_WriteProcessMemory_0b81 {
  strings:
    $key_0b81 = { 5c f3 [2] 6e d1 [2] 68 e4 [2] 46 e4 [2] 79 f8 }

  condition:
    any of them
}