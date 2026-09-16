rule TTP_XOR_WriteProcessMemory_f7de {
  strings:
    $key_f7de = { a0 ac [2] 92 8e [2] 94 bb [2] ba bb [2] 85 a7 }

  condition:
    any of them
}