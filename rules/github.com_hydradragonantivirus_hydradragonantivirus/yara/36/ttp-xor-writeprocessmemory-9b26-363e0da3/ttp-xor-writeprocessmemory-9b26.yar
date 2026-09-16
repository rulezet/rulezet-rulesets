rule TTP_XOR_WriteProcessMemory_9b26 {
  strings:
    $key_9b26 = { cc 54 [2] fe 76 [2] f8 43 [2] d6 43 [2] e9 5f }

  condition:
    any of them
}