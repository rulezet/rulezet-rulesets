rule TTP_XOR_WriteProcessMemory_955e {
  strings:
    $key_955e = { c2 2c [2] f0 0e [2] f6 3b [2] d8 3b [2] e7 27 }

  condition:
    any of them
}