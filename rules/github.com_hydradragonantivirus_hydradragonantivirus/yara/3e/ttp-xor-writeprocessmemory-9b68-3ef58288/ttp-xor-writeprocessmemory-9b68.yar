rule TTP_XOR_WriteProcessMemory_9b68 {
  strings:
    $key_9b68 = { cc 1a [2] fe 38 [2] f8 0d [2] d6 0d [2] e9 11 }

  condition:
    any of them
}