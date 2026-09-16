rule TTP_XOR_WriteProcessMemory_812e {
  strings:
    $key_812e = { d6 5c [2] e4 7e [2] e2 4b [2] cc 4b [2] f3 57 }

  condition:
    any of them
}