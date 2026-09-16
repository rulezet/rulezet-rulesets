rule TTP_XOR_WriteProcessMemory_9363 {
  strings:
    $key_9363 = { c4 11 [2] f6 33 [2] f0 06 [2] de 06 [2] e1 1a }

  condition:
    any of them
}