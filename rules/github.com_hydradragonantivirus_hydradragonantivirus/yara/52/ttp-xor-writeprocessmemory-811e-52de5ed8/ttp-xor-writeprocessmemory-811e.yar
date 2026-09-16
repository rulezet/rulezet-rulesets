rule TTP_XOR_WriteProcessMemory_811e {
  strings:
    $key_811e = { d6 6c [2] e4 4e [2] e2 7b [2] cc 7b [2] f3 67 }

  condition:
    any of them
}