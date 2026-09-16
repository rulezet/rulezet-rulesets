rule TTP_XOR_WriteProcessMemory_9252 {
  strings:
    $key_9252 = { c5 20 [2] f7 02 [2] f1 37 [2] df 37 [2] e0 2b }

  condition:
    any of them
}