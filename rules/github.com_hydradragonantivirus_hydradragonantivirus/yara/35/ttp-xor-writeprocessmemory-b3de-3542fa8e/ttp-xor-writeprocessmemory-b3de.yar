rule TTP_XOR_WriteProcessMemory_b3de {
  strings:
    $key_b3de = { e4 ac [2] d6 8e [2] d0 bb [2] fe bb [2] c1 a7 }

  condition:
    any of them
}