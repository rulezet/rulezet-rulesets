rule TTP_XOR_WriteProcessMemory_926b {
  strings:
    $key_926b = { c5 19 [2] f7 3b [2] f1 0e [2] df 0e [2] e0 12 }

  condition:
    any of them
}