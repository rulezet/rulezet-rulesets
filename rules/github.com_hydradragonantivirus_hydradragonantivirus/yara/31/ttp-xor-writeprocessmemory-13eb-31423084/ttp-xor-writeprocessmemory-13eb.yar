rule TTP_XOR_WriteProcessMemory_13eb {
  strings:
    $key_13eb = { 44 99 [2] 76 bb [2] 70 8e [2] 5e 8e [2] 61 92 }

  condition:
    any of them
}