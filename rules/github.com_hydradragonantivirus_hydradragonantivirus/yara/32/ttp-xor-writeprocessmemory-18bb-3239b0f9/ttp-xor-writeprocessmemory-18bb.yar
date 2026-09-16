rule TTP_XOR_WriteProcessMemory_18bb {
  strings:
    $key_18bb = { 4f c9 [2] 7d eb [2] 7b de [2] 55 de [2] 6a c2 }

  condition:
    any of them
}