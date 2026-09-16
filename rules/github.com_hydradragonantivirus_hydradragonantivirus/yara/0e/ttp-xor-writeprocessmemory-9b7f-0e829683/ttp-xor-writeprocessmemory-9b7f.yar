rule TTP_XOR_WriteProcessMemory_9b7f {
  strings:
    $key_9b7f = { cc 0d [2] fe 2f [2] f8 1a [2] d6 1a [2] e9 06 }

  condition:
    any of them
}