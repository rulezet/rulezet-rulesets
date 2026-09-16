rule TTP_XOR_WriteProcessMemory_827e {
  strings:
    $key_827e = { d5 0c [2] e7 2e [2] e1 1b [2] cf 1b [2] f0 07 }

  condition:
    any of them
}