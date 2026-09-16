rule TTP_XOR_WriteProcessMemory_b5de {
  strings:
    $key_b5de = { e2 ac [2] d0 8e [2] d6 bb [2] f8 bb [2] c7 a7 }

  condition:
    any of them
}