rule TTP_XOR_WriteProcessMemory_31eb {
  strings:
    $key_31eb = { 66 99 [2] 54 bb [2] 52 8e [2] 7c 8e [2] 43 92 }

  condition:
    any of them
}