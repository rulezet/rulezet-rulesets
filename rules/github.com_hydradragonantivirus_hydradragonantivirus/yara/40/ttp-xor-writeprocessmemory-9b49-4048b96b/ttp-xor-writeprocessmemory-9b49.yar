rule TTP_XOR_WriteProcessMemory_9b49 {
  strings:
    $key_9b49 = { cc 3b [2] fe 19 [2] f8 2c [2] d6 2c [2] e9 30 }

  condition:
    any of them
}