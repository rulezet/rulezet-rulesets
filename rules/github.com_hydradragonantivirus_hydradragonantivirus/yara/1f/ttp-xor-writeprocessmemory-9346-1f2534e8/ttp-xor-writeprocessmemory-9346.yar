rule TTP_XOR_WriteProcessMemory_9346 {
  strings:
    $key_9346 = { c4 34 [2] f6 16 [2] f0 23 [2] de 23 [2] e1 3f }

  condition:
    any of them
}