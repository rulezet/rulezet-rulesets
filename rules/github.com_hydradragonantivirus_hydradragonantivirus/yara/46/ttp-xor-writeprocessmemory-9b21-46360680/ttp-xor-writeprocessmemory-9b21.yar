rule TTP_XOR_WriteProcessMemory_9b21 {
  strings:
    $key_9b21 = { cc 53 [2] fe 71 [2] f8 44 [2] d6 44 [2] e9 58 }

  condition:
    any of them
}