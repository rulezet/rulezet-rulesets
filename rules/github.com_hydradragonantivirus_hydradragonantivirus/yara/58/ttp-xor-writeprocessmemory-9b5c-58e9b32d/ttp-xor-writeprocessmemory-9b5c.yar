rule TTP_XOR_WriteProcessMemory_9b5c {
  strings:
    $key_9b5c = { cc 2e [2] fe 0c [2] f8 39 [2] d6 39 [2] e9 25 }

  condition:
    any of them
}