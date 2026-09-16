rule TTP_XOR_WriteProcessMemory_9bee {
  strings:
    $key_9bee = { cc 9c [2] fe be [2] f8 8b [2] d6 8b [2] e9 97 }

  condition:
    any of them
}