rule TTP_XOR_WriteProcessMemory_872e {
  strings:
    $key_872e = { d0 5c [2] e2 7e [2] e4 4b [2] ca 4b [2] f5 57 }

  condition:
    any of them
}