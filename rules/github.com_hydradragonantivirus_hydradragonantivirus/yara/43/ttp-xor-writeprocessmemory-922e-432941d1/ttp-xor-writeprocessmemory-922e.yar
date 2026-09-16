rule TTP_XOR_WriteProcessMemory_922e {
  strings:
    $key_922e = { c5 5c [2] f7 7e [2] f1 4b [2] df 4b [2] e0 57 }

  condition:
    any of them
}