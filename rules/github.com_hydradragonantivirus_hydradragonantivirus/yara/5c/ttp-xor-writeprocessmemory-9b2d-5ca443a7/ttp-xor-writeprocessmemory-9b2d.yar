rule TTP_XOR_WriteProcessMemory_9b2d {
  strings:
    $key_9b2d = { cc 5f [2] fe 7d [2] f8 48 [2] d6 48 [2] e9 54 }

  condition:
    any of them
}