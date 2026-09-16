rule TTP_XOR_WriteProcessMemory_74eb {
  strings:
    $key_74eb = { 23 99 [2] 11 bb [2] 17 8e [2] 39 8e [2] 06 92 }

  condition:
    any of them
}