rule TTP_XOR_WriteProcessMemory_9368 {
  strings:
    $key_9368 = { c4 1a [2] f6 38 [2] f0 0d [2] de 0d [2] e1 11 }

  condition:
    any of them
}