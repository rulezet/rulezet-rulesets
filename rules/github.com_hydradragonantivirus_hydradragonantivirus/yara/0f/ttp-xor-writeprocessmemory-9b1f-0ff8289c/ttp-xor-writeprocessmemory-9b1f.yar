rule TTP_XOR_WriteProcessMemory_9b1f {
  strings:
    $key_9b1f = { cc 6d [2] fe 4f [2] f8 7a [2] d6 7a [2] e9 66 }

  condition:
    any of them
}