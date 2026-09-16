rule TTP_XOR_WriteProcessMemory_c5de {
  strings:
    $key_c5de = { 92 ac [2] a0 8e [2] a6 bb [2] 88 bb [2] b7 a7 }

  condition:
    any of them
}