rule TTP_XOR_WriteProcessMemory_9b51 {
  strings:
    $key_9b51 = { cc 23 [2] fe 01 [2] f8 34 [2] d6 34 [2] e9 28 }

  condition:
    any of them
}