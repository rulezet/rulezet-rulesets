rule TTP_XOR_WriteProcessMemory_5b84 {
  strings:
    $key_5b84 = { 0c f6 [2] 3e d4 [2] 38 e1 [2] 16 e1 [2] 29 fd }

  condition:
    any of them
}