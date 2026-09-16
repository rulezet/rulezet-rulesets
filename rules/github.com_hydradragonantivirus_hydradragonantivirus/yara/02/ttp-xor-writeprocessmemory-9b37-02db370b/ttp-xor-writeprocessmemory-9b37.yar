rule TTP_XOR_WriteProcessMemory_9b37 {
  strings:
    $key_9b37 = { cc 45 [2] fe 67 [2] f8 52 [2] d6 52 [2] e9 4e }

  condition:
    any of them
}