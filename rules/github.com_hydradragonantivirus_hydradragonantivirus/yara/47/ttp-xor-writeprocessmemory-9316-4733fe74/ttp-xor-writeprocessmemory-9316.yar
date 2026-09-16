rule TTP_XOR_WriteProcessMemory_9316 {
  strings:
    $key_9316 = { c4 64 [2] f6 46 [2] f0 73 [2] de 73 [2] e1 6f }

  condition:
    any of them
}