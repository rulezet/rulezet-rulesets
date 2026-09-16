rule TTP_XOR_WriteProcessMemory_870e {
  strings:
    $key_870e = { d0 7c [2] e2 5e [2] e4 6b [2] ca 6b [2] f5 77 }

  condition:
    any of them
}