rule TTP_XOR_WriteProcessMemory_9b5a {
  strings:
    $key_9b5a = { cc 28 [2] fe 0a [2] f8 3f [2] d6 3f [2] e9 23 }

  condition:
    any of them
}