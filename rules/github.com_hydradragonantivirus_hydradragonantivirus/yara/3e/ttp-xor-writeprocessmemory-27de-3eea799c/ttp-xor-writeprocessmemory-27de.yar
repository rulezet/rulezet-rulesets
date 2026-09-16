rule TTP_XOR_WriteProcessMemory_27de {
  strings:
    $key_27de = { 70 ac [2] 42 8e [2] 44 bb [2] 6a bb [2] 55 a7 }

  condition:
    any of them
}