rule TTP_XOR_WriteProcessMemory_a3de {
  strings:
    $key_a3de = { f4 ac [2] c6 8e [2] c0 bb [2] ee bb [2] d1 a7 }

  condition:
    any of them
}