rule TTP_XOR_WriteProcessMemory_e5bb {
  strings:
    $key_e5bb = { b2 c9 [2] 80 eb [2] 86 de [2] a8 de [2] 97 c2 }

  condition:
    any of them
}