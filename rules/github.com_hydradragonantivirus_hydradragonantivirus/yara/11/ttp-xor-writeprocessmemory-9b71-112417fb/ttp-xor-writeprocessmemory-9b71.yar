rule TTP_XOR_WriteProcessMemory_9b71 {
  strings:
    $key_9b71 = { cc 03 [2] fe 21 [2] f8 14 [2] d6 14 [2] e9 08 }

  condition:
    any of them
}