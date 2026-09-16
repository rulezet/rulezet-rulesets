rule TTP_XOR_WriteProcessMemory_814e {
  strings:
    $key_814e = { d6 3c [2] e4 1e [2] e2 2b [2] cc 2b [2] f3 37 }

  condition:
    any of them
}