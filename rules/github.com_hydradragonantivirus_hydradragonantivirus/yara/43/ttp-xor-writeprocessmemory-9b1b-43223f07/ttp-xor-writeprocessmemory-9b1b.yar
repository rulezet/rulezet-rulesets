rule TTP_XOR_WriteProcessMemory_9b1b {
  strings:
    $key_9b1b = { cc 69 [2] fe 4b [2] f8 7e [2] d6 7e [2] e9 62 }

  condition:
    any of them
}