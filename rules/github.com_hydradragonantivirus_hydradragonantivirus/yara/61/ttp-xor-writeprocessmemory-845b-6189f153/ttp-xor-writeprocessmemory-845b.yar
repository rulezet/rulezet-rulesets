rule TTP_XOR_WriteProcessMemory_845b {
  strings:
    $key_845b = { d3 29 [2] e1 0b [2] e7 3e [2] c9 3e [2] f6 22 }

  condition:
    any of them
}