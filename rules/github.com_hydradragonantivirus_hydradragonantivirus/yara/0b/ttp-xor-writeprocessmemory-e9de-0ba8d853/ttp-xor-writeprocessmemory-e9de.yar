rule TTP_XOR_WriteProcessMemory_e9de {
  strings:
    $key_e9de = { be ac [2] 8c 8e [2] 8a bb [2] a4 bb [2] 9b a7 }

  condition:
    any of them
}