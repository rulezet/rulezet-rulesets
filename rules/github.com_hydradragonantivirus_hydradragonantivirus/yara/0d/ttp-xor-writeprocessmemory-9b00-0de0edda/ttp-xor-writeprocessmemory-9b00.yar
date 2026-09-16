rule TTP_XOR_WriteProcessMemory_9b00 {
  strings:
    $key_9b00 = { cc 72 [2] fe 50 [2] f8 65 [2] d6 65 [2] e9 79 }

  condition:
    any of them
}