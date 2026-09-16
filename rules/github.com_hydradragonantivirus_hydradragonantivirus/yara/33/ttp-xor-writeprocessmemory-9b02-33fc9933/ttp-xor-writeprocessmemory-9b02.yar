rule TTP_XOR_WriteProcessMemory_9b02 {
  strings:
    $key_9b02 = { cc 70 [2] fe 52 [2] f8 67 [2] d6 67 [2] e9 7b }

  condition:
    any of them
}