rule TTP_XOR_WriteProcessMemory_01eb {
  strings:
    $key_01eb = { 56 99 [2] 64 bb [2] 62 8e [2] 4c 8e [2] 73 92 }

  condition:
    any of them
}