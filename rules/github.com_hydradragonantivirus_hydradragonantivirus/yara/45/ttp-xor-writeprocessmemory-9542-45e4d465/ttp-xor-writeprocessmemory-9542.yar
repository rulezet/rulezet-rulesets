rule TTP_XOR_WriteProcessMemory_9542 {
  strings:
    $key_9542 = { c2 30 [2] f0 12 [2] f6 27 [2] d8 27 [2] e7 3b }

  condition:
    any of them
}