rule TTP_XOR_WriteProcessMemory_26eb {
  strings:
    $key_26eb = { 71 99 [2] 43 bb [2] 45 8e [2] 6b 8e [2] 54 92 }

  condition:
    any of them
}