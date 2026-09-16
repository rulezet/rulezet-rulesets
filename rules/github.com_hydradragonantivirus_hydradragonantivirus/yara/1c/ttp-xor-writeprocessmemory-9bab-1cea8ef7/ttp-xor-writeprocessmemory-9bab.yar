rule TTP_XOR_WriteProcessMemory_9bab {
  strings:
    $key_9bab = { cc d9 [2] fe fb [2] f8 ce [2] d6 ce [2] e9 d2 }

  condition:
    any of them
}