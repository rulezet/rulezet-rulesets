rule TTP_XOR_WriteProcessMemory_845e {
  strings:
    $key_845e = { d3 2c [2] e1 0e [2] e7 3b [2] c9 3b [2] f6 27 }

  condition:
    any of them
}