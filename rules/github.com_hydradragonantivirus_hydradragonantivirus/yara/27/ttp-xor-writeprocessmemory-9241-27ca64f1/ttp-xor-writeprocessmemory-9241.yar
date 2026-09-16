rule TTP_XOR_WriteProcessMemory_9241 {
  strings:
    $key_9241 = { c5 33 [2] f7 11 [2] f1 24 [2] df 24 [2] e0 38 }

  condition:
    any of them
}