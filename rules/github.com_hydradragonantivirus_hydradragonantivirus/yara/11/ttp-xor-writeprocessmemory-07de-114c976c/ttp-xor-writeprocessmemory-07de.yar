rule TTP_XOR_WriteProcessMemory_07de {
  strings:
    $key_07de = { 50 ac [2] 62 8e [2] 64 bb [2] 4a bb [2] 75 a7 }

  condition:
    any of them
}