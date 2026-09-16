rule TTP_XOR_WriteProcessMemory_9ba4 {
  strings:
    $key_9ba4 = { cc d6 [2] fe f4 [2] f8 c1 [2] d6 c1 [2] e9 dd }

  condition:
    any of them
}