rule TTP_XOR_WriteProcessMemory_b4eb {
  strings:
    $key_b4eb = { e3 99 [2] d1 bb [2] d7 8e [2] f9 8e [2] c6 92 }

  condition:
    any of them
}