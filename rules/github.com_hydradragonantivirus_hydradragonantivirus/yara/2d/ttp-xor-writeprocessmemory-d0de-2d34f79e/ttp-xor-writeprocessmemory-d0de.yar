rule TTP_XOR_WriteProcessMemory_d0de {
  strings:
    $key_d0de = { 87 ac [2] b5 8e [2] b3 bb [2] 9d bb [2] a2 a7 }

  condition:
    any of them
}