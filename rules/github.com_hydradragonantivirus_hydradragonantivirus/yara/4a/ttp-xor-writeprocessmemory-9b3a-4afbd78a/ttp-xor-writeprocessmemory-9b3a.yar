rule TTP_XOR_WriteProcessMemory_9b3a {
  strings:
    $key_9b3a = { cc 48 [2] fe 6a [2] f8 5f [2] d6 5f [2] e9 43 }

  condition:
    any of them
}