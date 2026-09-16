rule TTP_XOR_WriteProcessMemory_7b81 {
  strings:
    $key_7b81 = { 2c f3 [2] 1e d1 [2] 18 e4 [2] 36 e4 [2] 09 f8 }

  condition:
    any of them
}