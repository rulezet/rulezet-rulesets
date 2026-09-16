rule TTP_XOR_WriteProcessMemory_843e {
  strings:
    $key_843e = { d3 4c [2] e1 6e [2] e7 5b [2] c9 5b [2] f6 47 }

  condition:
    any of them
}