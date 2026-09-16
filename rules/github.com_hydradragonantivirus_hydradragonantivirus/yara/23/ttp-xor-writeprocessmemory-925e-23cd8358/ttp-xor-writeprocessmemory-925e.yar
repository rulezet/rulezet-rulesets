rule TTP_XOR_WriteProcessMemory_925e {
  strings:
    $key_925e = { c5 2c [2] f7 0e [2] f1 3b [2] df 3b [2] e0 27 }

  condition:
    any of them
}