rule TTP_XOR_WriteProcessMemory_53de {
  strings:
    $key_53de = { 04 ac [2] 36 8e [2] 30 bb [2] 1e bb [2] 21 a7 }

  condition:
    any of them
}