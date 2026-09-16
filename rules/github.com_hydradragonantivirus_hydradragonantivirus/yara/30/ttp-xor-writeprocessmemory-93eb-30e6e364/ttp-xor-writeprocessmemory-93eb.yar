rule TTP_XOR_WriteProcessMemory_93eb {
  strings:
    $key_93eb = { c4 99 [2] f6 bb [2] f0 8e [2] de 8e [2] e1 92 }

  condition:
    any of them
}