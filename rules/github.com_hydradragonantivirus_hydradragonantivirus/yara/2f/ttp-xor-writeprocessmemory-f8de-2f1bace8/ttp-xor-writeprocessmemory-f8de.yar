rule TTP_XOR_WriteProcessMemory_f8de {
  strings:
    $key_f8de = { af ac [2] 9d 8e [2] 9b bb [2] b5 bb [2] 8a a7 }

  condition:
    any of them
}