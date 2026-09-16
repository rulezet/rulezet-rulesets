rule TTP_XOR_WriteProcessMemory_9243 {
  strings:
    $key_9243 = { c5 31 [2] f7 13 [2] f1 26 [2] df 26 [2] e0 3a }

  condition:
    any of them
}