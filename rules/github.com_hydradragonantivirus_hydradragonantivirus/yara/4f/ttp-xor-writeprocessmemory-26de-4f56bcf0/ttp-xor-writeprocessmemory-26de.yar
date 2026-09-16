rule TTP_XOR_WriteProcessMemory_26de {
  strings:
    $key_26de = { 71 ac [2] 43 8e [2] 45 bb [2] 6b bb [2] 54 a7 }

  condition:
    any of them
}