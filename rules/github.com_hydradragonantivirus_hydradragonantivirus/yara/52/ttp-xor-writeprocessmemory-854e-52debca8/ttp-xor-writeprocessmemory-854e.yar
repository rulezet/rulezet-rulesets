rule TTP_XOR_WriteProcessMemory_854e {
  strings:
    $key_854e = { d2 3c [2] e0 1e [2] e6 2b [2] c8 2b [2] f7 37 }

  condition:
    any of them
}