rule TTP_XOR_WriteProcessMemory_9384 {
  strings:
    $key_9384 = { c4 f6 [2] f6 d4 [2] f0 e1 [2] de e1 [2] e1 fd }

  condition:
    any of them
}