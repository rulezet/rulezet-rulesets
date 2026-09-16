rule TTP_XOR_WriteProcessMemory_9b6b {
  strings:
    $key_9b6b = { cc 19 [2] fe 3b [2] f8 0e [2] d6 0e [2] e9 12 }

  condition:
    any of them
}