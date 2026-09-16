rule TTP_XOR_WriteProcessMemory_9b5e {
  strings:
    $key_9b5e = { cc 2c [2] fe 0e [2] f8 3b [2] d6 3b [2] e9 27 }

  condition:
    any of them
}