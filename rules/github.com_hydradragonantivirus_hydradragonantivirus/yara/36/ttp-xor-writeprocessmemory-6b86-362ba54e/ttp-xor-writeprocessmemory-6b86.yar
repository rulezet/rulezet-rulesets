rule TTP_XOR_WriteProcessMemory_6b86 {
  strings:
    $key_6b86 = { 3c f4 [2] 0e d6 [2] 08 e3 [2] 26 e3 [2] 19 ff }

  condition:
    any of them
}