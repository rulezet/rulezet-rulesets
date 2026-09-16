rule TTP_XOR_WriteProcessMemory_c6de {
  strings:
    $key_c6de = { 91 ac [2] a3 8e [2] a5 bb [2] 8b bb [2] b4 a7 }

  condition:
    any of them
}