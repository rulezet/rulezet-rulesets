rule TTP_XOR_WriteProcessMemory_56de {
  strings:
    $key_56de = { 01 ac [2] 33 8e [2] 35 bb [2] 1b bb [2] 24 a7 }

  condition:
    any of them
}