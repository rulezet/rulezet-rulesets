rule TTP_XOR_WriteProcessMemory_974e {
  strings:
    $key_974e = { c0 3c [2] f2 1e [2] f4 2b [2] da 2b [2] e5 37 }

  condition:
    any of them
}