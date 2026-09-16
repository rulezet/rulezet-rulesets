rule TTP_XOR_WriteProcessMemory_0b85 {
  strings:
    $key_0b85 = { 5c f7 [2] 6e d5 [2] 68 e0 [2] 46 e0 [2] 79 fc }

  condition:
    any of them
}