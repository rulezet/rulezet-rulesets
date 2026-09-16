rule TTP_XOR_WriteProcessMemory_9bef {
  strings:
    $key_9bef = { cc 9d [2] fe bf [2] f8 8a [2] d6 8a [2] e9 96 }

  condition:
    any of them
}