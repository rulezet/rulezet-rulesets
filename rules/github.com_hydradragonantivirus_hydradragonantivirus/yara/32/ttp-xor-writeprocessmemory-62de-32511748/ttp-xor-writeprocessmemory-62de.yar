rule TTP_XOR_WriteProcessMemory_62de {
  strings:
    $key_62de = { 35 ac [2] 07 8e [2] 01 bb [2] 2f bb [2] 10 a7 }

  condition:
    any of them
}