rule TTP_XOR_WriteProcessMemory_844e {
  strings:
    $key_844e = { d3 3c [2] e1 1e [2] e7 2b [2] c9 2b [2] f6 37 }

  condition:
    any of them
}