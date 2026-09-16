rule TTP_XOR_WriteProcessMemory_877e {
  strings:
    $key_877e = { d0 0c [2] e2 2e [2] e4 1b [2] ca 1b [2] f5 07 }

  condition:
    any of them
}