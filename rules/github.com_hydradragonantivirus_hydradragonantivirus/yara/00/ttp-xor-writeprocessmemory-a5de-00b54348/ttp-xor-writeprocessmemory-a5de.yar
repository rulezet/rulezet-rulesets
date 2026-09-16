rule TTP_XOR_WriteProcessMemory_a5de {
  strings:
    $key_a5de = { f2 ac [2] c0 8e [2] c6 bb [2] e8 bb [2] d7 a7 }

  condition:
    any of them
}