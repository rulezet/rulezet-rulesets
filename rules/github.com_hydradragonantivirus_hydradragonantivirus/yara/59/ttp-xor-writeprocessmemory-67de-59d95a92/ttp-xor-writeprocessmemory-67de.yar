rule TTP_XOR_WriteProcessMemory_67de {
  strings:
    $key_67de = { 30 ac [2] 02 8e [2] 04 bb [2] 2a bb [2] 15 a7 }

  condition:
    any of them
}