rule TTP_XOR_WriteProcessMemory_7b86 {
  strings:
    $key_7b86 = { 2c f4 [2] 1e d6 [2] 18 e3 [2] 36 e3 [2] 09 ff }

  condition:
    any of them
}