rule TTP_XOR_WriteProcessMemory_65de {
  strings:
    $key_65de = { 32 ac [2] 00 8e [2] 06 bb [2] 28 bb [2] 17 a7 }

  condition:
    any of them
}