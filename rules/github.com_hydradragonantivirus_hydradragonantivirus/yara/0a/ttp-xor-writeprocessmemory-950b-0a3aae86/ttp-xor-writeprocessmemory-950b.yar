rule TTP_XOR_WriteProcessMemory_950b {
  strings:
    $key_950b = { c2 79 [2] f0 5b [2] f6 6e [2] d8 6e [2] e7 72 }

  condition:
    any of them
}