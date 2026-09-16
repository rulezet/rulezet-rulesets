rule TTP_XOR_WriteProcessMemory_9b2b {
  strings:
    $key_9b2b = { cc 59 [2] fe 7b [2] f8 4e [2] d6 4e [2] e9 52 }

  condition:
    any of them
}