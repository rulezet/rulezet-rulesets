rule TTP_XOR_WriteProcessMemory_a4eb {
  strings:
    $key_a4eb = { f3 99 [2] c1 bb [2] c7 8e [2] e9 8e [2] d6 92 }

  condition:
    any of them
}