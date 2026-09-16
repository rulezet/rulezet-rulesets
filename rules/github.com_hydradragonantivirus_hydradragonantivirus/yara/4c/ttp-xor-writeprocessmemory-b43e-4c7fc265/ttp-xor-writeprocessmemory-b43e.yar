rule TTP_XOR_WriteProcessMemory_b43e {
  strings:
    $key_b43e = { e3 4c [2] d1 6e [2] d7 5b [2] f9 5b [2] c6 47 }

  condition:
    any of them
}