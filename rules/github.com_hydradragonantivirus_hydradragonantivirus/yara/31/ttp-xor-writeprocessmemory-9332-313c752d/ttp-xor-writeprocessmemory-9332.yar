rule TTP_XOR_WriteProcessMemory_9332 {
  strings:
    $key_9332 = { c4 40 [2] f6 62 [2] f0 57 [2] de 57 [2] e1 4b }

  condition:
    any of them
}