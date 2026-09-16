rule TTP_XOR_WriteProcessMemory_92de {
  strings:
    $key_92de = { c5 ac [2] f7 8e [2] f1 bb [2] df bb [2] e0 a7 }

  condition:
    any of them
}