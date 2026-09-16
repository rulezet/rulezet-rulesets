rule TTP_XOR_WriteProcessMemory_926e {
  strings:
    $key_926e = { c5 1c [2] f7 3e [2] f1 0b [2] df 0b [2] e0 17 }

  condition:
    any of them
}