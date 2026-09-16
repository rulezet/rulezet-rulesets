rule TTP_XOR_WriteProcessMemory_875e {
  strings:
    $key_875e = { d0 2c [2] e2 0e [2] e4 3b [2] ca 3b [2] f5 27 }

  condition:
    any of them
}