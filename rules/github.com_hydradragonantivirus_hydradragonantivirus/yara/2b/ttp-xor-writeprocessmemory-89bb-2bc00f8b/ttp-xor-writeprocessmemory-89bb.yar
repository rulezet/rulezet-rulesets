rule TTP_XOR_WriteProcessMemory_89bb {
  strings:
    $key_89bb = { de c9 [2] ec eb [2] ea de [2] c4 de [2] fb c2 }

  condition:
    any of them
}