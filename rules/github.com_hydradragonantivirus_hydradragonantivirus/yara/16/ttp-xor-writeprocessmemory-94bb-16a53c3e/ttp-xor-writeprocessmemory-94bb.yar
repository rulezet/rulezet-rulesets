rule TTP_XOR_WriteProcessMemory_94bb {
  strings:
    $key_94bb = { c3 c9 [2] f1 eb [2] f7 de [2] d9 de [2] e6 c2 }

  condition:
    any of them
}