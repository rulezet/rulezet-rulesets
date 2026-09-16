rule TTP_XOR_WriteProcessMemory_03de {
  strings:
    $key_03de = { 54 ac [2] 66 8e [2] 60 bb [2] 4e bb [2] 71 a7 }

  condition:
    any of them
}