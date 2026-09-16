rule TTP_XOR_WriteProcessMemory_9362 {
  strings:
    $key_9362 = { c4 10 [2] f6 32 [2] f0 07 [2] de 07 [2] e1 1b }

  condition:
    any of them
}