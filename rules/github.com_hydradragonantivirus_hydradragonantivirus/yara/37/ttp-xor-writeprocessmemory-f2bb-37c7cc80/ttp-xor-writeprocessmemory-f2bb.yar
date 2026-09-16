rule TTP_XOR_WriteProcessMemory_f2bb {
  strings:
    $key_f2bb = { a5 c9 [2] 97 eb [2] 91 de [2] bf de [2] 80 c2 }

  condition:
    any of them
}