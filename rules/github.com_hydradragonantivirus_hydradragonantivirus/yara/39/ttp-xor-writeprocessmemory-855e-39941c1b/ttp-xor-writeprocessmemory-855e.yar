rule TTP_XOR_WriteProcessMemory_855e {
  strings:
    $key_855e = { d2 2c [2] e0 0e [2] e6 3b [2] c8 3b [2] f7 27 }

  condition:
    any of them
}