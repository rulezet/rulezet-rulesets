rule TTP_XOR_WriteProcessMemory_927b {
  strings:
    $key_927b = { c5 09 [2] f7 2b [2] f1 1e [2] df 1e [2] e0 02 }

  condition:
    any of them
}