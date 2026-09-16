rule TTP_XOR_WriteProcessMemory_9516 {
  strings:
    $key_9516 = { c2 64 [2] f0 46 [2] f6 73 [2] d8 73 [2] e7 6f }

  condition:
    any of them
}