rule TTP_XOR_WriteProcessMemory_9536 {
  strings:
    $key_9536 = { c2 44 [2] f0 66 [2] f6 53 [2] d8 53 [2] e7 4f }

  condition:
    any of them
}