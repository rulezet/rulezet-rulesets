rule TTP_XOR_WriteProcessMemory_c0de {
  strings:
    $key_c0de = { 97 ac [2] a5 8e [2] a3 bb [2] 8d bb [2] b2 a7 }

  condition:
    any of them
}