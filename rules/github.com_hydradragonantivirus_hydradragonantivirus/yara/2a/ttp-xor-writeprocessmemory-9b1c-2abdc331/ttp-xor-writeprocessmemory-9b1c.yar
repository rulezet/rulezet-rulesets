rule TTP_XOR_WriteProcessMemory_9b1c {
  strings:
    $key_9b1c = { cc 6e [2] fe 4c [2] f8 79 [2] d6 79 [2] e9 65 }

  condition:
    any of them
}