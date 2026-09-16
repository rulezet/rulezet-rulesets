rule TTP_XOR_WriteProcessMemory_9b67 {
  strings:
    $key_9b67 = { cc 15 [2] fe 37 [2] f8 02 [2] d6 02 [2] e9 1e }

  condition:
    any of them
}