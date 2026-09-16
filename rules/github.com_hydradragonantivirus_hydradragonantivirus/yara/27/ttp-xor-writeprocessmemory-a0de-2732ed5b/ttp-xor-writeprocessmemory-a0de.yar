rule TTP_XOR_WriteProcessMemory_a0de {
  strings:
    $key_a0de = { f7 ac [2] c5 8e [2] c3 bb [2] ed bb [2] d2 a7 }

  condition:
    any of them
}