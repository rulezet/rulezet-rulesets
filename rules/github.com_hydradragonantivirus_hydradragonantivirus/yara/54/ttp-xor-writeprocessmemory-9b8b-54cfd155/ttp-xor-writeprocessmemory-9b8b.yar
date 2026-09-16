rule TTP_XOR_WriteProcessMemory_9b8b {
  strings:
    $key_9b8b = { cc f9 [2] fe db [2] f8 ee [2] d6 ee [2] e9 f2 }

  condition:
    any of them
}