rule TTP_XOR_WriteProcessMemory_dec9 {
  strings:
    $key_dec9 = { 89 bb [2] bb 99 [2] bd ac [2] 93 ac [2] ac b0 }

  condition:
    any of them
}