rule TTP_XOR_WriteProcessMemory_9b76 {
  strings:
    $key_9b76 = { cc 04 [2] fe 26 [2] f8 13 [2] d6 13 [2] e9 0f }

  condition:
    any of them
}