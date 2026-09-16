rule TTP_XOR_WriteProcessMemory_9b48 {
  strings:
    $key_9b48 = { cc 3a [2] fe 18 [2] f8 2d [2] d6 2d [2] e9 31 }

  condition:
    any of them
}