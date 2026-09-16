rule TTP_XOR_WriteProcessMemory_e1bb {
  strings:
    $key_e1bb = { b6 c9 [2] 84 eb [2] 82 de [2] ac de [2] 93 c2 }

  condition:
    any of them
}