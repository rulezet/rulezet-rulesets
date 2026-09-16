rule TTP_XOR_WriteProcessMemory_9b7a {
  strings:
    $key_9b7a = { cc 08 [2] fe 2a [2] f8 1f [2] d6 1f [2] e9 03 }

  condition:
    any of them
}