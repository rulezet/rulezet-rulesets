rule TTP_XOR_WriteProcessMemory_9b60 {
  strings:
    $key_9b60 = { cc 12 [2] fe 30 [2] f8 05 [2] d6 05 [2] e9 19 }

  condition:
    any of them
}