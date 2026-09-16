rule TTP_XOR_WriteProcessMemory_904b {
  strings:
    $key_904b = { c7 39 [2] f5 1b [2] f3 2e [2] dd 2e [2] e2 32 }

  condition:
    any of them
}