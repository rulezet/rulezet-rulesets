rule TTP_XOR_WriteProcessMemory_9462 {
  strings:
    $key_9462 = { c3 10 [2] f1 32 [2] f7 07 [2] d9 07 [2] e6 1b }

  condition:
    any of them
}