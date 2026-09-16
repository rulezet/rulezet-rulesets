rule TTP_XOR_WriteProcessMemory_850e {
  strings:
    $key_850e = { d2 7c [2] e0 5e [2] e6 6b [2] c8 6b [2] f7 77 }

  condition:
    any of them
}