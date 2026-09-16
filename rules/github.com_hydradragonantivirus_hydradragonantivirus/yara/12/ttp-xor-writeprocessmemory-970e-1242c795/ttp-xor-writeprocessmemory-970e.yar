rule TTP_XOR_WriteProcessMemory_970e {
  strings:
    $key_970e = { c0 7c [2] f2 5e [2] f4 6b [2] da 6b [2] e5 77 }

  condition:
    any of them
}