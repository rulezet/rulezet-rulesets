rule TTP_XOR_WriteProcessMemory_9263 {
  strings:
    $key_9263 = { c5 11 [2] f7 33 [2] f1 06 [2] df 06 [2] e0 1a }

  condition:
    any of them
}