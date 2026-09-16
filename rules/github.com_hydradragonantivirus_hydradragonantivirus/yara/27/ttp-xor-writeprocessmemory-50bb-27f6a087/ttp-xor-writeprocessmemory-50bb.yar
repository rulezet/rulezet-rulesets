rule TTP_XOR_WriteProcessMemory_50bb {
  strings:
    $key_50bb = { 07 c9 [2] 35 eb [2] 33 de [2] 1d de [2] 22 c2 }

  condition:
    any of them
}