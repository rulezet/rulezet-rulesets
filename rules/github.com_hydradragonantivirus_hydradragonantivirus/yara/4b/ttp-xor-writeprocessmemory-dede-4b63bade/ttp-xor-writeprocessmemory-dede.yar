rule TTP_XOR_WriteProcessMemory_dede {
  strings:
    $key_dede = { 89 ac [2] bb 8e [2] bd bb [2] 93 bb [2] ac a7 }

  condition:
    any of them
}