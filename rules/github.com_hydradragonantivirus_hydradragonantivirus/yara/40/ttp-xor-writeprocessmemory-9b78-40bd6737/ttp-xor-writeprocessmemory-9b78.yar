rule TTP_XOR_WriteProcessMemory_9b78 {
  strings:
    $key_9b78 = { cc 0a [2] fe 28 [2] f8 1d [2] d6 1d [2] e9 01 }

  condition:
    any of them
}