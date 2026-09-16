rule TTP_XOR_WriteProcessMemory_a7de {
  strings:
    $key_a7de = { f0 ac [2] c2 8e [2] c4 bb [2] ea bb [2] d5 a7 }

  condition:
    any of them
}