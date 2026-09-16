rule TTP_XOR_WriteProcessMemory_67eb {
  strings:
    $key_67eb = { 30 99 [2] 02 bb [2] 04 8e [2] 2a 8e [2] 15 92 }

  condition:
    any of them
}