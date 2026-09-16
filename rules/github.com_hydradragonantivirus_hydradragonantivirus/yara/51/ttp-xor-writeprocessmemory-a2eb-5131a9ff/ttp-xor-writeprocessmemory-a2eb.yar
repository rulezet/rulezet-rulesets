rule TTP_XOR_WriteProcessMemory_a2eb {
  strings:
    $key_a2eb = { f5 99 [2] c7 bb [2] c1 8e [2] ef 8e [2] d0 92 }

  condition:
    any of them
}