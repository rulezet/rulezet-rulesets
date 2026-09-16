rule TTP_XOR_WriteProcessMemory_63eb {
  strings:
    $key_63eb = { 34 99 [2] 06 bb [2] 00 8e [2] 2e 8e [2] 11 92 }

  condition:
    any of them
}