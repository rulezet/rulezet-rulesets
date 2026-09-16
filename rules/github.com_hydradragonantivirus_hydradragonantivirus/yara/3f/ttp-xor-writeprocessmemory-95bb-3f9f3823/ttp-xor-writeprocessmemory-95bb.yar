rule TTP_XOR_WriteProcessMemory_95bb {
  strings:
    $key_95bb = { c2 c9 [2] f0 eb [2] f6 de [2] d8 de [2] e7 c2 }

  condition:
    any of them
}