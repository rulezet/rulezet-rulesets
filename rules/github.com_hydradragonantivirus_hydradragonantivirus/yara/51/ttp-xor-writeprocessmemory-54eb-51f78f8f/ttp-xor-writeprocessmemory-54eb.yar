rule TTP_XOR_WriteProcessMemory_54eb {
  strings:
    $key_54eb = { 03 99 [2] 31 bb [2] 37 8e [2] 19 8e [2] 26 92 }

  condition:
    any of them
}