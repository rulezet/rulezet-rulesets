rule TTP_XOR_WriteProcessMemory_9343 {
  strings:
    $key_9343 = { c4 31 [2] f6 13 [2] f0 26 [2] de 26 [2] e1 3a }

  condition:
    any of them
}