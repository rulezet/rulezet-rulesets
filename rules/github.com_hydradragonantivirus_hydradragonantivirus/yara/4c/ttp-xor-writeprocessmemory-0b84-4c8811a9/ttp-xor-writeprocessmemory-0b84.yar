rule TTP_XOR_WriteProcessMemory_0b84 {
  strings:
    $key_0b84 = { 5c f6 [2] 6e d4 [2] 68 e1 [2] 46 e1 [2] 79 fd }

  condition:
    any of them
}