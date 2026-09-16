rule TTP_XOR_WriteProcessMemory_9b47 {
  strings:
    $key_9b47 = { cc 35 [2] fe 17 [2] f8 22 [2] d6 22 [2] e9 3e }

  condition:
    any of them
}