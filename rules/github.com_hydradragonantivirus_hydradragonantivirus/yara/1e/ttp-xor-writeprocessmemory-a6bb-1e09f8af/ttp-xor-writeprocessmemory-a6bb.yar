rule TTP_XOR_WriteProcessMemory_a6bb {
  strings:
    $key_a6bb = { f1 c9 [2] c3 eb [2] c5 de [2] eb de [2] d4 c2 }

  condition:
    any of them
}