rule TTP_XOR_WriteProcessMemory_964e {
  strings:
    $key_964e = { c1 3c [2] f3 1e [2] f5 2b [2] db 2b [2] e4 37 }

  condition:
    any of them
}