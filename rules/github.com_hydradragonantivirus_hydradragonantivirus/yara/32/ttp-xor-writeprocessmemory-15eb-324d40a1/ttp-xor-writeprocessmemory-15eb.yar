rule TTP_XOR_WriteProcessMemory_15eb {
  strings:
    $key_15eb = { 42 99 [2] 70 bb [2] 76 8e [2] 58 8e [2] 67 92 }

  condition:
    any of them
}