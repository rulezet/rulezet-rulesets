rule TTP_XOR_WriteProcessMemory_9342 {
  strings:
    $key_9342 = { c4 30 [2] f6 12 [2] f0 27 [2] de 27 [2] e1 3b }

  condition:
    any of them
}