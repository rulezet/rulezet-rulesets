rule TTP_XOR_WriteProcessMemory_9b86 {
  strings:
    $key_9b86 = { cc f4 [2] fe d6 [2] f8 e3 [2] d6 e3 [2] e9 ff }

  condition:
    any of them
}