rule TTP_XOR_WriteProcessMemory_e1eb {
  strings:
    $key_e1eb = { b6 99 [2] 84 bb [2] 82 8e [2] ac 8e [2] 93 92 }

  condition:
    any of them
}