rule TTP_XOR_WriteProcessMemory_9522 {
  strings:
    $key_9522 = { c2 50 [2] f0 72 [2] f6 47 [2] d8 47 [2] e7 5b }

  condition:
    any of them
}