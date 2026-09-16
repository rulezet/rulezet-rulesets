rule TTP_XOR_WriteProcessMemory_968e {
  strings:
    $key_968e = { c1 fc [2] f3 de [2] f5 eb [2] db eb [2] e4 f7 }

  condition:
    any of them
}