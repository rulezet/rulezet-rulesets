rule TTP_XOR_WriteProcessMemory_824e {
  strings:
    $key_824e = { d5 3c [2] e7 1e [2] e1 2b [2] cf 2b [2] f0 37 }

  condition:
    any of them
}