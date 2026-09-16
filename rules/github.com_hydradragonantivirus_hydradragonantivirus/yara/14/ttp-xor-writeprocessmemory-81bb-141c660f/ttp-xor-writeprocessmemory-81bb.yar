rule TTP_XOR_WriteProcessMemory_81bb {
  strings:
    $key_81bb = { d6 c9 [2] e4 eb [2] e2 de [2] cc de [2] f3 c2 }

  condition:
    any of them
}