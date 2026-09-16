rule TTP_XOR_WriteProcessMemory_e4de {
  strings:
    $key_e4de = { b3 ac [2] 81 8e [2] 87 bb [2] a9 bb [2] 96 a7 }

  condition:
    any of them
}