rule TTP_XOR_WriteProcessMemory_e7de {
  strings:
    $key_e7de = { b0 ac [2] 82 8e [2] 84 bb [2] aa bb [2] 95 a7 }

  condition:
    any of them
}