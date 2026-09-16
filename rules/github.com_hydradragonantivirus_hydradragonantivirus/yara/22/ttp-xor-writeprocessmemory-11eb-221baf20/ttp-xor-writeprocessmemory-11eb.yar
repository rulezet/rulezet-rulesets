rule TTP_XOR_WriteProcessMemory_11eb {
  strings:
    $key_11eb = { 46 99 [2] 74 bb [2] 72 8e [2] 5c 8e [2] 63 92 }

  condition:
    any of them
}