rule TTP_XOR_WriteProcessMemory_9594 {
  strings:
    $key_9594 = { c2 e6 [2] f0 c4 [2] f6 f1 [2] d8 f1 [2] e7 ed }

  condition:
    any of them
}