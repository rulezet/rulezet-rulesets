rule TTP_XOR_WriteProcessMemory_88bb {
  strings:
    $key_88bb = { df c9 [2] ed eb [2] eb de [2] c5 de [2] fa c2 }

  condition:
    any of them
}