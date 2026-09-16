rule TTP_XOR_WriteProcessMemory_902e {
  strings:
    $key_902e = { c7 5c [2] f5 7e [2] f3 4b [2] dd 4b [2] e2 57 }

  condition:
    any of them
}