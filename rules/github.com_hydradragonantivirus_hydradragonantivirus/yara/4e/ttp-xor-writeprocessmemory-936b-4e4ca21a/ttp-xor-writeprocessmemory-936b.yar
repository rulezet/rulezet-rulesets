rule TTP_XOR_WriteProcessMemory_936b {
  strings:
    $key_936b = { c4 19 [2] f6 3b [2] f0 0e [2] de 0e [2] e1 12 }

  condition:
    any of them
}