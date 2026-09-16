rule TTP_XOR_WriteProcessMemory_9b4b {
  strings:
    $key_9b4b = { cc 39 [2] fe 1b [2] f8 2e [2] d6 2e [2] e9 32 }

  condition:
    any of them
}