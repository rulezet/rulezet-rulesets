rule TTP_XOR_WriteProcessMemory_9379 {
  strings:
    $key_9379 = { c4 0b [2] f6 29 [2] f0 1c [2] de 1c [2] e1 00 }

  condition:
    any of them
}