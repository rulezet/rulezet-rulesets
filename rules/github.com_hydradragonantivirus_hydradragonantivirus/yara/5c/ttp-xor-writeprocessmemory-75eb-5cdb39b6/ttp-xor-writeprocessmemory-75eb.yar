rule TTP_XOR_WriteProcessMemory_75eb {
  strings:
    $key_75eb = { 22 99 [2] 10 bb [2] 16 8e [2] 38 8e [2] 07 92 }

  condition:
    any of them
}