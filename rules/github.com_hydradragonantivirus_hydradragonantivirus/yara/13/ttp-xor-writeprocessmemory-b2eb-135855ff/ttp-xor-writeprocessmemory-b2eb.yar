rule TTP_XOR_WriteProcessMemory_b2eb {
  strings:
    $key_b2eb = { e5 99 [2] d7 bb [2] d1 8e [2] ff 8e [2] c0 92 }

  condition:
    any of them
}