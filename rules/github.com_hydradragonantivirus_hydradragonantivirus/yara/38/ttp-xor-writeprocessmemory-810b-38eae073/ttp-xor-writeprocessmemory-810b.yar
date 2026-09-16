rule TTP_XOR_WriteProcessMemory_810b {
  strings:
    $key_810b = { d6 79 [2] e4 5b [2] e2 6e [2] cc 6e [2] f3 72 }

  condition:
    any of them
}