rule TTP_XOR_WriteProcessMemory_9b4e {
  strings:
    $key_9b4e = { cc 3c [2] fe 1e [2] f8 2b [2] d6 2b [2] e9 37 }

  condition:
    any of them
}