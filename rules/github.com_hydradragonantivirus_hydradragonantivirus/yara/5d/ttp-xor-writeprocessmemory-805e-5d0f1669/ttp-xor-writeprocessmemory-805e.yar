rule TTP_XOR_WriteProcessMemory_805e {
  strings:
    $key_805e = { d7 2c [2] e5 0e [2] e3 3b [2] cd 3b [2] f2 27 }

  condition:
    any of them
}