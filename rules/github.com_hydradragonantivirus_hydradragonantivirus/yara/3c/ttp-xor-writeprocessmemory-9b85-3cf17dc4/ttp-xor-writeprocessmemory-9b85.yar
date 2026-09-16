rule TTP_XOR_WriteProcessMemory_9b85 {
  strings:
    $key_9b85 = { cc f7 [2] fe d5 [2] f8 e0 [2] d6 e0 [2] e9 fc }

  condition:
    any of them
}