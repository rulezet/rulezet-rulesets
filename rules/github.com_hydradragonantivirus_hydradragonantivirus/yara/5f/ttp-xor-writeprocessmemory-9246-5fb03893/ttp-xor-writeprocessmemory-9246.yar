rule TTP_XOR_WriteProcessMemory_9246 {
  strings:
    $key_9246 = { c5 34 [2] f7 16 [2] f1 23 [2] df 23 [2] e0 3f }

  condition:
    any of them
}