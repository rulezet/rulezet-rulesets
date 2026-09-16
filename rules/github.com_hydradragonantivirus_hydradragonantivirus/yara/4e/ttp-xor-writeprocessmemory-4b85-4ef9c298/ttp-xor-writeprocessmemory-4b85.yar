rule TTP_XOR_WriteProcessMemory_4b85 {
  strings:
    $key_4b85 = { 1c f7 [2] 2e d5 [2] 28 e0 [2] 06 e0 [2] 39 fc }

  condition:
    any of them
}