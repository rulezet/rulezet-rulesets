rule TTP_XOR_WriteProcessMemory_30de {
  strings:
    $key_30de = { 67 ac [2] 55 8e [2] 53 bb [2] 7d bb [2] 42 a7 }

  condition:
    any of them
}