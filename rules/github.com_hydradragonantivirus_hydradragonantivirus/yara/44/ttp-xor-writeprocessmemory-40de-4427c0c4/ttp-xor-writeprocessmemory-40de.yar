rule TTP_XOR_WriteProcessMemory_40de {
  strings:
    $key_40de = { 17 ac [2] 25 8e [2] 23 bb [2] 0d bb [2] 32 a7 }

  condition:
    any of them
}