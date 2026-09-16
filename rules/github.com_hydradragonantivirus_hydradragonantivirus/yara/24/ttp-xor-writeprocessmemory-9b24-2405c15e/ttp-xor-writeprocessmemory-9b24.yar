rule TTP_XOR_WriteProcessMemory_9b24 {
  strings:
    $key_9b24 = { cc 56 [2] fe 74 [2] f8 41 [2] d6 41 [2] e9 5d }

  condition:
    any of them
}