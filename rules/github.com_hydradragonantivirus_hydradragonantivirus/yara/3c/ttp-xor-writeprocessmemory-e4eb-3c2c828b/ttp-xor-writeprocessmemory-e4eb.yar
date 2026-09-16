rule TTP_XOR_WriteProcessMemory_e4eb {
  strings:
    $key_e4eb = { b3 99 [2] 81 bb [2] 87 8e [2] a9 8e [2] 96 92 }

  condition:
    any of them
}