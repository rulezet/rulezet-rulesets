rule TTP_XOR_WriteProcessMemory_9212 {
  strings:
    $key_9212 = { c5 60 [2] f7 42 [2] f1 77 [2] df 77 [2] e0 6b }

  condition:
    any of them
}