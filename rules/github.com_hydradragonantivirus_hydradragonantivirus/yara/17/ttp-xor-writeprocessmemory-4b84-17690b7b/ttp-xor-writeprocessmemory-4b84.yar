rule TTP_XOR_WriteProcessMemory_4b84 {
  strings:
    $key_4b84 = { 1c f6 [2] 2e d4 [2] 28 e1 [2] 06 e1 [2] 39 fd }

  condition:
    any of them
}