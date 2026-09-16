rule TTP_XOR_WriteProcessMemory_9b46 {
  strings:
    $key_9b46 = { cc 34 [2] fe 16 [2] f8 23 [2] d6 23 [2] e9 3f }

  condition:
    any of them
}