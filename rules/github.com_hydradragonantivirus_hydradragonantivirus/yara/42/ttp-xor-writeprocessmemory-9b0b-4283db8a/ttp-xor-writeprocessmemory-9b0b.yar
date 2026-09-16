rule TTP_XOR_WriteProcessMemory_9b0b {
  strings:
    $key_9b0b = { cc 79 [2] fe 5b [2] f8 6e [2] d6 6e [2] e9 72 }

  condition:
    any of them
}