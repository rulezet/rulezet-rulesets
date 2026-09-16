rule TTP_XOR_WriteProcessMemory_52de {
  strings:
    $key_52de = { 05 ac [2] 37 8e [2] 31 bb [2] 1f bb [2] 20 a7 }

  condition:
    any of them
}