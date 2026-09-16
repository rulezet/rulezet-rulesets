rule TTP_XOR_WriteProcessMemory_816e {
  strings:
    $key_816e = { d6 1c [2] e4 3e [2] e2 0b [2] cc 0b [2] f3 17 }

  condition:
    any of them
}