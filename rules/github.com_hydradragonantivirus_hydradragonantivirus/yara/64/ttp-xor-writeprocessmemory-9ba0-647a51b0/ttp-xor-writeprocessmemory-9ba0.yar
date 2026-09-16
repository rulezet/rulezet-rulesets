rule TTP_XOR_WriteProcessMemory_9ba0 {
  strings:
    $key_9ba0 = { cc d2 [2] fe f0 [2] f8 c5 [2] d6 c5 [2] e9 d9 }

  condition:
    any of them
}