rule TTP_XOR_WriteProcessMemory_40eb {
  strings:
    $key_40eb = { 17 99 [2] 25 bb [2] 23 8e [2] 0d 8e [2] 32 92 }

  condition:
    any of them
}