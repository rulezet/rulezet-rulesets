rule TTP_XOR_WriteProcessMemory_25bb {
  strings:
    $key_25bb = { 72 c9 [2] 40 eb [2] 46 de [2] 68 de [2] 57 c2 }

  condition:
    any of them
}