rule TTP_XOR_WriteProcessMemory_5b86 {
  strings:
    $key_5b86 = { 0c f4 [2] 3e d6 [2] 38 e3 [2] 16 e3 [2] 29 ff }

  condition:
    any of them
}