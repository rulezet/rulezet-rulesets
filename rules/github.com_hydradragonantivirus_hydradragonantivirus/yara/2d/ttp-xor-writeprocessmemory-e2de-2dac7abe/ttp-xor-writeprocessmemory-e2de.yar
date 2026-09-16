rule TTP_XOR_WriteProcessMemory_e2de {
  strings:
    $key_e2de = { b5 ac [2] 87 8e [2] 81 bb [2] af bb [2] 90 a7 }

  condition:
    any of them
}