rule TTP_XOR_WriteProcessMemory_e1de {
  strings:
    $key_e1de = { b6 ac [2] 84 8e [2] 82 bb [2] ac bb [2] 93 a7 }

  condition:
    any of them
}