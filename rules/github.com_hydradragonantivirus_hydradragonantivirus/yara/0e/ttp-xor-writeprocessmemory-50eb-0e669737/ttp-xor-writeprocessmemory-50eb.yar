rule TTP_XOR_WriteProcessMemory_50eb {
  strings:
    $key_50eb = { 07 99 [2] 35 bb [2] 33 8e [2] 1d 8e [2] 22 92 }

  condition:
    any of them
}