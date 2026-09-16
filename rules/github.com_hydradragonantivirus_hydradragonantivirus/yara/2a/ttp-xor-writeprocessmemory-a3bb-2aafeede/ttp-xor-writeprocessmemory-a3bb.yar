rule TTP_XOR_WriteProcessMemory_a3bb {
  strings:
    $key_a3bb = { f4 c9 [2] c6 eb [2] c0 de [2] ee de [2] d1 c2 }

  condition:
    any of them
}