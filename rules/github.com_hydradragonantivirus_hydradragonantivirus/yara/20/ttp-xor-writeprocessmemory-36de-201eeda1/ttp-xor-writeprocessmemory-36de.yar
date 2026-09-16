rule TTP_XOR_WriteProcessMemory_36de {
  strings:
    $key_36de = { 61 ac [2] 53 8e [2] 55 bb [2] 7b bb [2] 44 a7 }

  condition:
    any of them
}