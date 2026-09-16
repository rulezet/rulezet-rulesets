rule TTP_XOR_WriteProcessMemory_a0eb {
  strings:
    $key_a0eb = { f7 99 [2] c5 bb [2] c3 8e [2] ed 8e [2] d2 92 }

  condition:
    any of them
}