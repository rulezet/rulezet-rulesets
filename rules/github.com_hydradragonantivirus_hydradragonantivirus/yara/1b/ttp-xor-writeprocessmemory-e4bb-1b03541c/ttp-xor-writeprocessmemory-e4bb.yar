rule TTP_XOR_WriteProcessMemory_e4bb {
  strings:
    $key_e4bb = { b3 c9 [2] 81 eb [2] 87 de [2] a9 de [2] 96 c2 }

  condition:
    any of them
}