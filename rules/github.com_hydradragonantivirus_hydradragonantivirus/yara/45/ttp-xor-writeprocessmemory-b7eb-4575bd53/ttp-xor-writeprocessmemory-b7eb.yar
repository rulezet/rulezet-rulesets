rule TTP_XOR_WriteProcessMemory_b7eb {
  strings:
    $key_b7eb = { e0 99 [2] d2 bb [2] d4 8e [2] fa 8e [2] c5 92 }

  condition:
    any of them
}