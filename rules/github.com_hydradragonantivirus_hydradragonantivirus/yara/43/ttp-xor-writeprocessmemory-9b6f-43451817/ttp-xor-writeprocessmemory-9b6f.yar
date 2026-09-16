rule TTP_XOR_WriteProcessMemory_9b6f {
  strings:
    $key_9b6f = { cc 1d [2] fe 3f [2] f8 0a [2] d6 0a [2] e9 16 }

  condition:
    any of them
}