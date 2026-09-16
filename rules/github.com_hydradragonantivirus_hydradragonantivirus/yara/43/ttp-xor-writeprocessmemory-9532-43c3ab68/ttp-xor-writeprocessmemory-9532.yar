rule TTP_XOR_WriteProcessMemory_9532 {
  strings:
    $key_9532 = { c2 40 [2] f0 62 [2] f6 57 [2] d8 57 [2] e7 4b }

  condition:
    any of them
}