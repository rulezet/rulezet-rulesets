rule TTP_XOR_WriteProcessMemory_970b {
  strings:
    $key_970b = { c0 79 [2] f2 5b [2] f4 6e [2] da 6e [2] e5 72 }

  condition:
    any of them
}