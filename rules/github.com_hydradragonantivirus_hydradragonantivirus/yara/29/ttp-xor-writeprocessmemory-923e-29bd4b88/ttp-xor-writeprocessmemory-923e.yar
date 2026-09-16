rule TTP_XOR_WriteProcessMemory_923e {
  strings:
    $key_923e = { c5 4c [2] f7 6e [2] f1 5b [2] df 5b [2] e0 47 }

  condition:
    any of them
}