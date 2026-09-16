rule TTP_XOR_WriteProcessMemory_3b86 {
  strings:
    $key_3b86 = { 6c f4 [2] 5e d6 [2] 58 e3 [2] 76 e3 [2] 49 ff }

  condition:
    any of them
}