rule TTP_XOR_WriteProcessMemory_9b11 {
  strings:
    $key_9b11 = { cc 63 [2] fe 41 [2] f8 74 [2] d6 74 [2] e9 68 }

  condition:
    any of them
}