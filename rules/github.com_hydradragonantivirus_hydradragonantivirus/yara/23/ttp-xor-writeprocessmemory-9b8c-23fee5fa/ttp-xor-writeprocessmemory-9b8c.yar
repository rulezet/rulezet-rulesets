rule TTP_XOR_WriteProcessMemory_9b8c {
  strings:
    $key_9b8c = { cc fe [2] fe dc [2] f8 e9 [2] d6 e9 [2] e9 f5 }

  condition:
    any of them
}