rule TTP_XOR_WriteProcessMemory_963e {
  strings:
    $key_963e = { c1 4c [2] f3 6e [2] f5 5b [2] db 5b [2] e4 47 }

  condition:
    any of them
}