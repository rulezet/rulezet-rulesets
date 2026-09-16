rule TTP_XOR_WriteProcessMemory_30eb {
  strings:
    $key_30eb = { 67 99 [2] 55 bb [2] 53 8e [2] 7d 8e [2] 42 92 }

  condition:
    any of them
}