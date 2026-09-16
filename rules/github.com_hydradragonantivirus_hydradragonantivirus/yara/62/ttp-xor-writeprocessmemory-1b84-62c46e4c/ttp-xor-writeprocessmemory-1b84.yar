rule TTP_XOR_WriteProcessMemory_1b84 {
  strings:
    $key_1b84 = { 4c f6 [2] 7e d4 [2] 78 e1 [2] 56 e1 [2] 69 fd }

  condition:
    any of them
}