rule TTP_XOR_WriteProcessMemory_9442 {
  strings:
    $key_9442 = { c3 30 [2] f1 12 [2] f7 27 [2] d9 27 [2] e6 3b }

  condition:
    any of them
}