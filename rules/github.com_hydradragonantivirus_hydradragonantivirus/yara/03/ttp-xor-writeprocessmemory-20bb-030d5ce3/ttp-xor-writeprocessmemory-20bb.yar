rule TTP_XOR_WriteProcessMemory_20bb {
  strings:
    $key_20bb = { 77 c9 [2] 45 eb [2] 43 de [2] 6d de [2] 52 c2 }

  condition:
    any of them
}