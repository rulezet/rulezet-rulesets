rule TTP_XOR_WriteProcessMemory_9b2c {
  strings:
    $key_9b2c = { cc 5e [2] fe 7c [2] f8 49 [2] d6 49 [2] e9 55 }

  condition:
    any of them
}