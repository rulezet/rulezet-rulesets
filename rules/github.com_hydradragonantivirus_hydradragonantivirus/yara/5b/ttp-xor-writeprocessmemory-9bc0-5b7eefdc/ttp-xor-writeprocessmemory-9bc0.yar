rule TTP_XOR_WriteProcessMemory_9bc0 {
  strings:
    $key_9bc0 = { cc b2 [2] fe 90 [2] f8 a5 [2] d6 a5 [2] e9 b9 }

  condition:
    any of them
}