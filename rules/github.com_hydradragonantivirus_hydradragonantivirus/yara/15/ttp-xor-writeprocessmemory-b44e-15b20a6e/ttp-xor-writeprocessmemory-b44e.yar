rule TTP_XOR_WriteProcessMemory_b44e {
  strings:
    $key_b44e = { e3 3c [2] d1 1e [2] d7 2b [2] f9 2b [2] c6 37 }

  condition:
    any of them
}