rule TTP_XOR_WriteProcessMemory_71de {
  strings:
    $key_71de = { 26 ac [2] 14 8e [2] 12 bb [2] 3c bb [2] 03 a7 }

  condition:
    any of them
}