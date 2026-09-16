rule TTP_XOR_WriteProcessMemory_9d9e {
  strings:
    $key_9d9e = { ca ec [2] f8 ce [2] fe fb [2] d0 fb [2] ef e7 }

  condition:
    any of them
}