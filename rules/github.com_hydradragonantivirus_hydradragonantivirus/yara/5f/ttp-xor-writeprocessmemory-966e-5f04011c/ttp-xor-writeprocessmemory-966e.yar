rule TTP_XOR_WriteProcessMemory_966e {
  strings:
    $key_966e = { c1 1c [2] f3 3e [2] f5 0b [2] db 0b [2] e4 17 }

  condition:
    any of them
}