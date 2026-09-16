rule TTP_XOR_WriteProcessMemory_9b07 {
  strings:
    $key_9b07 = { cc 75 [2] fe 57 [2] f8 62 [2] d6 62 [2] e9 7e }

  condition:
    any of them
}