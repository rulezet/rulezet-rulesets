rule TTP_XOR_WriteProcessMemory_9563 {
  strings:
    $key_9563 = { c2 11 [2] f0 33 [2] f6 06 [2] d8 06 [2] e7 1a }

  condition:
    any of them
}