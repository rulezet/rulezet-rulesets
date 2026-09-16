rule TTP_XOR_WriteProcessMemory_9b23 {
  strings:
    $key_9b23 = { cc 51 [2] fe 73 [2] f8 46 [2] d6 46 [2] e9 5a }

  condition:
    any of them
}