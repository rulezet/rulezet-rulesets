rule TTP_XOR_WriteProcessMemory_1b81 {
  strings:
    $key_1b81 = { 4c f3 [2] 7e d1 [2] 78 e4 [2] 56 e4 [2] 69 f8 }

  condition:
    any of them
}