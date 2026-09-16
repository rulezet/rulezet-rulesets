rule TTP_XOR_WriteProcessMemory_a1de {
  strings:
    $key_a1de = { f6 ac [2] c4 8e [2] c2 bb [2] ec bb [2] d3 a7 }

  condition:
    any of them
}