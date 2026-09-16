rule TTP_XOR_WriteProcessMemory_964b {
  strings:
    $key_964b = { c1 39 [2] f3 1b [2] f5 2e [2] db 2e [2] e4 32 }

  condition:
    any of them
}