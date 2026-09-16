rule TTP_XOR_WriteProcessMemory_30bb {
  strings:
    $key_30bb = { 67 c9 [2] 55 eb [2] 53 de [2] 7d de [2] 42 c2 }

  condition:
    any of them
}