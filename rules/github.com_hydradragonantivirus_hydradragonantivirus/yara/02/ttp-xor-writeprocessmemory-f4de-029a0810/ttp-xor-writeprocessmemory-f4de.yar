rule TTP_XOR_WriteProcessMemory_f4de {
  strings:
    $key_f4de = { a3 ac [2] 91 8e [2] 97 bb [2] b9 bb [2] 86 a7 }

  condition:
    any of them
}