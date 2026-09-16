rule TTP_XOR_WriteProcessMemory_9b61 {
  strings:
    $key_9b61 = { cc 13 [2] fe 31 [2] f8 04 [2] d6 04 [2] e9 18 }

  condition:
    any of them
}