rule TTP_XOR_WriteProcessMemory_85eb {
  strings:
    $key_85eb = { d2 99 [2] e0 bb [2] e6 8e [2] c8 8e [2] f7 92 }

  condition:
    any of them
}