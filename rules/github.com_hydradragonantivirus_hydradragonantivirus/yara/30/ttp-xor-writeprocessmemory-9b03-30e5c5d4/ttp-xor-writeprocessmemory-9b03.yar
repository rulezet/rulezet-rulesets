rule TTP_XOR_WriteProcessMemory_9b03 {
  strings:
    $key_9b03 = { cc 71 [2] fe 53 [2] f8 66 [2] d6 66 [2] e9 7a }

  condition:
    any of them
}