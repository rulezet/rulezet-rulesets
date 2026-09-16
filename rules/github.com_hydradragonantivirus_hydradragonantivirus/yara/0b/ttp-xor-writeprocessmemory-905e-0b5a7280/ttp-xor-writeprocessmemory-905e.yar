rule TTP_XOR_WriteProcessMemory_905e {
  strings:
    $key_905e = { c7 2c [2] f5 0e [2] f3 3b [2] dd 3b [2] e2 27 }

  condition:
    any of them
}