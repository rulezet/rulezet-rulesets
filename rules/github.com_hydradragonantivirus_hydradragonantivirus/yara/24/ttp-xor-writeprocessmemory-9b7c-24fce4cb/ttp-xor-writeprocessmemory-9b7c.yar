rule TTP_XOR_WriteProcessMemory_9b7c {
  strings:
    $key_9b7c = { cc 0e [2] fe 2c [2] f8 19 [2] d6 19 [2] e9 05 }

  condition:
    any of them
}