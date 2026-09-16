rule TTP_XOR_WriteProcessMemory_9b80 {
  strings:
    $key_9b80 = { cc f2 [2] fe d0 [2] f8 e5 [2] d6 e5 [2] e9 f9 }

  condition:
    any of them
}