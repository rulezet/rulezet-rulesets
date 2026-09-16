rule TTP_XOR_WriteProcessMemory_9378 {
  strings:
    $key_9378 = { c4 0a [2] f6 28 [2] f0 1d [2] de 1d [2] e1 01 }

  condition:
    any of them
}