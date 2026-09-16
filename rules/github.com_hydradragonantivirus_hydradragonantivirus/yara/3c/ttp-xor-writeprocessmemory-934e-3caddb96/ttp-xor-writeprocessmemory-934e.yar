rule TTP_XOR_WriteProcessMemory_934e {
  strings:
    $key_934e = { c4 3c [2] f6 1e [2] f0 2b [2] de 2b [2] e1 37 }

  condition:
    any of them
}