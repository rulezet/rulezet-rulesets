rule TTP_XOR_WriteProcessMemory_847b {
  strings:
    $key_847b = { d3 09 [2] e1 2b [2] e7 1e [2] c9 1e [2] f6 02 }

  condition:
    any of them
}