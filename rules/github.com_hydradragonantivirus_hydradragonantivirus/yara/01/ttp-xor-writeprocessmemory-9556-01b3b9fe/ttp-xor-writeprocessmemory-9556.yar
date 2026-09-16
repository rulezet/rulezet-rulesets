rule TTP_XOR_WriteProcessMemory_9556 {
  strings:
    $key_9556 = { c2 24 [2] f0 06 [2] f6 33 [2] d8 33 [2] e7 2f }

  condition:
    any of them
}