rule TTP_XOR_WriteProcessMemory_874e {
  strings:
    $key_874e = { d0 3c [2] e2 1e [2] e4 2b [2] ca 2b [2] f5 37 }

  condition:
    any of them
}