rule TTP_XOR_WriteProcessMemory_9562 {
  strings:
    $key_9562 = { c2 10 [2] f0 32 [2] f6 07 [2] d8 07 [2] e7 1b }

  condition:
    any of them
}