rule TTP_XOR_WriteProcessMemory_9b31 {
  strings:
    $key_9b31 = { cc 43 [2] fe 61 [2] f8 54 [2] d6 54 [2] e9 48 }

  condition:
    any of them
}