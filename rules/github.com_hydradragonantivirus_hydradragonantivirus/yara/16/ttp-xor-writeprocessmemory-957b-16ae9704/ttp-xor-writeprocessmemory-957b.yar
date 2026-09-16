rule TTP_XOR_WriteProcessMemory_957b {
  strings:
    $key_957b = { c2 09 [2] f0 2b [2] f6 1e [2] d8 1e [2] e7 02 }

  condition:
    any of them
}