rule TTP_XOR_WriteProcessMemory_965e {
  strings:
    $key_965e = { c1 2c [2] f3 0e [2] f5 3b [2] db 3b [2] e4 27 }

  condition:
    any of them
}