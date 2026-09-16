rule TTP_XOR_WriteProcessMemory_66de {
  strings:
    $key_66de = { 31 ac [2] 03 8e [2] 05 bb [2] 2b bb [2] 14 a7 }

  condition:
    any of them
}