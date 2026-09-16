rule TTP_XOR_WriteProcessMemory_ccde {
  strings:
    $key_ccde = { 9b ac [2] a9 8e [2] af bb [2] 81 bb [2] be a7 }

  condition:
    any of them
}