rule TTP_XOR_WriteProcessMemory_47eb {
  strings:
    $key_47eb = { 10 99 [2] 22 bb [2] 24 8e [2] 0a 8e [2] 35 92 }

  condition:
    any of them
}