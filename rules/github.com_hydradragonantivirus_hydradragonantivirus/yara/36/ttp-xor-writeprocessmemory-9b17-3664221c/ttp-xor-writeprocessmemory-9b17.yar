rule TTP_XOR_WriteProcessMemory_9b17 {
  strings:
    $key_9b17 = { cc 65 [2] fe 47 [2] f8 72 [2] d6 72 [2] e9 6e }

  condition:
    any of them
}