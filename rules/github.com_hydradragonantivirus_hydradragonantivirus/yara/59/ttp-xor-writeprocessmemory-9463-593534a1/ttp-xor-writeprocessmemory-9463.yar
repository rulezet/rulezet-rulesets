rule TTP_XOR_WriteProcessMemory_9463 {
  strings:
    $key_9463 = { c3 11 [2] f1 33 [2] f7 06 [2] d9 06 [2] e6 1a }

  condition:
    any of them
}