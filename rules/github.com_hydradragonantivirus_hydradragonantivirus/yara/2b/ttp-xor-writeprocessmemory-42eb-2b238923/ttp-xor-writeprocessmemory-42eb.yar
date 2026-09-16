rule TTP_XOR_WriteProcessMemory_42eb {
  strings:
    $key_42eb = { 15 99 [2] 27 bb [2] 21 8e [2] 0f 8e [2] 30 92 }

  condition:
    any of them
}