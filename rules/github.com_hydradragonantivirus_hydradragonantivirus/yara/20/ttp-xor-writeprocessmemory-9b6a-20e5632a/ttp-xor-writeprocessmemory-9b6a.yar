rule TTP_XOR_WriteProcessMemory_9b6a {
  strings:
    $key_9b6a = { cc 18 [2] fe 3a [2] f8 0f [2] d6 0f [2] e9 13 }

  condition:
    any of them
}