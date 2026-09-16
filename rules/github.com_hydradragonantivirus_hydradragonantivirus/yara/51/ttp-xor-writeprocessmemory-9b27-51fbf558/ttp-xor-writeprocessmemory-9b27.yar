rule TTP_XOR_WriteProcessMemory_9b27 {
  strings:
    $key_9b27 = { cc 55 [2] fe 77 [2] f8 42 [2] d6 42 [2] e9 5e }

  condition:
    any of them
}