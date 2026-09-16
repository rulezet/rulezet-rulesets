rule TTP_XOR_WriteProcessMemory_10de {
  strings:
    $key_10de = { 47 ac [2] 75 8e [2] 73 bb [2] 5d bb [2] 62 a7 }

  condition:
    any of them
}