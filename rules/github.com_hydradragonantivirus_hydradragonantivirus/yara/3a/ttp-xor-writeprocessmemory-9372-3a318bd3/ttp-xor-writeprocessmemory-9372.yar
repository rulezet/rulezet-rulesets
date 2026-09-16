rule TTP_XOR_WriteProcessMemory_9372 {
  strings:
    $key_9372 = { c4 00 [2] f6 22 [2] f0 17 [2] de 17 [2] e1 0b }

  condition:
    any of them
}