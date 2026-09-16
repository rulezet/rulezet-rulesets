rule TTP_XOR_WriteProcessMemory_e3de {
  strings:
    $key_e3de = { b4 ac [2] 86 8e [2] 80 bb [2] ae bb [2] 91 a7 }

  condition:
    any of them
}