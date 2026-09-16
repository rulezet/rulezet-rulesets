rule TTP_XOR_WriteProcessMemory_72de {
  strings:
    $key_72de = { 25 ac [2] 17 8e [2] 11 bb [2] 3f bb [2] 00 a7 }

  condition:
    any of them
}