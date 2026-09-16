rule TTP_XOR_WriteProcessMemory_816c {
  strings:
    $key_816c = { d6 1e [2] e4 3c [2] e2 09 [2] cc 09 [2] f3 15 }

  condition:
    any of them
}