rule TTP_XOR_WriteProcessMemory_e7eb {
  strings:
    $key_e7eb = { b0 99 [2] 82 bb [2] 84 8e [2] aa 8e [2] 95 92 }

  condition:
    any of them
}