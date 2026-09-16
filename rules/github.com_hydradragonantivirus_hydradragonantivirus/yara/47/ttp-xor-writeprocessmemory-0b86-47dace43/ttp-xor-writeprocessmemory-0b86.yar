rule TTP_XOR_WriteProcessMemory_0b86 {
  strings:
    $key_0b86 = { 5c f4 [2] 6e d6 [2] 68 e3 [2] 46 e3 [2] 79 ff }

  condition:
    any of them
}