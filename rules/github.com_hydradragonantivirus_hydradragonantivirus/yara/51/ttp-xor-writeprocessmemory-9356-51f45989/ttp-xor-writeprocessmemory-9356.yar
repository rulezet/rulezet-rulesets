rule TTP_XOR_WriteProcessMemory_9356 {
  strings:
    $key_9356 = { c4 24 [2] f6 06 [2] f0 33 [2] de 33 [2] e1 2f }

  condition:
    any of them
}