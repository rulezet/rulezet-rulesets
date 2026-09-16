rule TTP_XOR_WriteProcessMemory_9b62 {
  strings:
    $key_9b62 = { cc 10 [2] fe 32 [2] f8 07 [2] d6 07 [2] e9 1b }

  condition:
    any of them
}