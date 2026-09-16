rule TTP_XOR_WriteProcessMemory_46eb {
  strings:
    $key_46eb = { 11 99 [2] 23 bb [2] 25 8e [2] 0b 8e [2] 34 92 }

  condition:
    any of them
}