rule TTP_XOR_WriteProcessMemory_966c {
  strings:
    $key_966c = { c1 1e [2] f3 3c [2] f5 09 [2] db 09 [2] e4 15 }

  condition:
    any of them
}