rule TTP_XOR_WriteProcessMemory_815e {
  strings:
    $key_815e = { d6 2c [2] e4 0e [2] e2 3b [2] cc 3b [2] f3 27 }

  condition:
    any of them
}