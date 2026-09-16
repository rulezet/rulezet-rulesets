rule TTP_XOR_WriteProcessMemory_a2bb {
  strings:
    $key_a2bb = { f5 c9 [2] c7 eb [2] c1 de [2] ef de [2] d0 c2 }

  condition:
    any of them
}