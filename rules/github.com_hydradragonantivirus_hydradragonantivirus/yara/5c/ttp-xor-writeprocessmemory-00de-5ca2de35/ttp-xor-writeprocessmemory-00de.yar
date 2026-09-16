rule TTP_XOR_WriteProcessMemory_00de {
  strings:
    $key_00de = { 57 ac [2] 65 8e [2] 63 bb [2] 4d bb [2] 72 a7 }

  condition:
    any of them
}