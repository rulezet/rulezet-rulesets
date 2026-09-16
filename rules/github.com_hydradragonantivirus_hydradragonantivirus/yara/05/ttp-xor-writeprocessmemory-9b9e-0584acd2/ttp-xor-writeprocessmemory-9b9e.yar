rule TTP_XOR_WriteProcessMemory_9b9e {
  strings:
    $key_9b9e = { cc ec [2] fe ce [2] f8 fb [2] d6 fb [2] e9 e7 }

  condition:
    any of them
}