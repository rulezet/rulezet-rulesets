rule TTP_XOR_WriteProcessMemory_c8de {
  strings:
    $key_c8de = { 9f ac [2] ad 8e [2] ab bb [2] 85 bb [2] ba a7 }

  condition:
    any of them
}