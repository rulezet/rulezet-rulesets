rule TTP_XOR_WriteProcessMemory_57de {
  strings:
    $key_57de = { 00 ac [2] 32 8e [2] 34 bb [2] 1a bb [2] 25 a7 }

  condition:
    any of them
}