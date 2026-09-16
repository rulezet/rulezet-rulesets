rule TTP_XOR_WriteProcessMemory_9b43 {
  strings:
    $key_9b43 = { cc 31 [2] fe 13 [2] f8 26 [2] d6 26 [2] e9 3a }

  condition:
    any of them
}