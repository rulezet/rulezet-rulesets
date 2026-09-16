rule TTP_XOR_WriteProcessMemory_975e {
  strings:
    $key_975e = { c0 2c [2] f2 0e [2] f4 3b [2] da 3b [2] e5 27 }

  condition:
    any of them
}