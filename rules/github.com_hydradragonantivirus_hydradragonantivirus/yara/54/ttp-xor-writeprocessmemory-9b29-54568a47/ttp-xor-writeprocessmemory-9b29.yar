rule TTP_XOR_WriteProcessMemory_9b29 {
  strings:
    $key_9b29 = { cc 5b [2] fe 79 [2] f8 4c [2] d6 4c [2] e9 50 }

  condition:
    any of them
}