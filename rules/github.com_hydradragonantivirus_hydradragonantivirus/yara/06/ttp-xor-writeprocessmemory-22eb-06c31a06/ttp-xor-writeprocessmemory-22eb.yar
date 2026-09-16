rule TTP_XOR_WriteProcessMemory_22eb {
  strings:
    $key_22eb = { 75 99 [2] 47 bb [2] 41 8e [2] 6f 8e [2] 50 92 }

  condition:
    any of them
}