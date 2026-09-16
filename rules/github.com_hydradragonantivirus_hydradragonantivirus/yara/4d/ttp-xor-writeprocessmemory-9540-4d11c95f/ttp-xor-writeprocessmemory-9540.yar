rule TTP_XOR_WriteProcessMemory_9540 {
  strings:
    $key_9540 = { c2 32 [2] f0 10 [2] f6 25 [2] d8 25 [2] e7 39 }

  condition:
    any of them
}