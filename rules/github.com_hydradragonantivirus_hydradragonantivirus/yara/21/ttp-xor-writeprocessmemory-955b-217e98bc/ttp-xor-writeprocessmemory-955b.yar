rule TTP_XOR_WriteProcessMemory_955b {
  strings:
    $key_955b = { c2 29 [2] f0 0b [2] f6 3e [2] d8 3e [2] e7 22 }

  condition:
    any of them
}