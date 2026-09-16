rule TTP_XOR_WriteProcessMemory_5b81 {
  strings:
    $key_5b81 = { 0c f3 [2] 3e d1 [2] 38 e4 [2] 16 e4 [2] 29 f8 }

  condition:
    any of them
}