rule TTP_XOR_WriteProcessMemory_9b30 {
  strings:
    $key_9b30 = { cc 42 [2] fe 60 [2] f8 55 [2] d6 55 [2] e9 49 }

  condition:
    any of them
}