rule TTP_XOR_WriteProcessMemory_930b {
  strings:
    $key_930b = { c4 79 [2] f6 5b [2] f0 6e [2] de 6e [2] e1 72 }

  condition:
    any of them
}