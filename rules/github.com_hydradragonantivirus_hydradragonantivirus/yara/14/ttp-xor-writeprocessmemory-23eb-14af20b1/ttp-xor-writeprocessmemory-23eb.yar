rule TTP_XOR_WriteProcessMemory_23eb {
  strings:
    $key_23eb = { 74 99 [2] 46 bb [2] 40 8e [2] 6e 8e [2] 51 92 }

  condition:
    any of them
}