rule TTP_XOR_WriteProcessMemory_e0de {
  strings:
    $key_e0de = { b7 ac [2] 85 8e [2] 83 bb [2] ad bb [2] 92 a7 }

  condition:
    any of them
}