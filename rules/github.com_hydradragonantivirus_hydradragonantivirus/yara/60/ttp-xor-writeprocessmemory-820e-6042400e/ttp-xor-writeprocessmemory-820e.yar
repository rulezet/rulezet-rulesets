rule TTP_XOR_WriteProcessMemory_820e {
  strings:
    $key_820e = { d5 7c [2] e7 5e [2] e1 6b [2] cf 6b [2] f0 77 }

  condition:
    any of them
}