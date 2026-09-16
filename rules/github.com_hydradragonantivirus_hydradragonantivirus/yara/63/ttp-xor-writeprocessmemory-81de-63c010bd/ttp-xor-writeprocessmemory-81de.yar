rule TTP_XOR_WriteProcessMemory_81de {
  strings:
    $key_81de = { d6 ac [2] e4 8e [2] e2 bb [2] cc bb [2] f3 a7 }

  condition:
    any of them
}