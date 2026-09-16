rule TTP_XOR_WriteProcessMemory_9b0a {
  strings:
    $key_9b0a = { cc 78 [2] fe 5a [2] f8 6f [2] d6 6f [2] e9 73 }

  condition:
    any of them
}