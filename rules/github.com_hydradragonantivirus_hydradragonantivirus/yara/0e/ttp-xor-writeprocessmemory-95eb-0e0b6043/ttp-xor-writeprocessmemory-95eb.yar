rule TTP_XOR_WriteProcessMemory_95eb {
  strings:
    $key_95eb = { c2 99 [2] f0 bb [2] f6 8e [2] d8 8e [2] e7 92 }

  condition:
    any of them
}