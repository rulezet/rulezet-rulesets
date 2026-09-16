rule TTP_XOR_WriteProcessMemory_b4de {
  strings:
    $key_b4de = { e3 ac [2] d1 8e [2] d7 bb [2] f9 bb [2] c6 a7 }

  condition:
    any of them
}