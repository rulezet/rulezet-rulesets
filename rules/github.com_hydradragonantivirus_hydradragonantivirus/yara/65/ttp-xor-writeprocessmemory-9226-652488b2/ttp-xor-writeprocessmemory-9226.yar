rule TTP_XOR_WriteProcessMemory_9226 {
  strings:
    $key_9226 = { c5 54 [2] f7 76 [2] f1 43 [2] df 43 [2] e0 5f }

  condition:
    any of them
}