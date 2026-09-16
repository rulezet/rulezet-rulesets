rule TTP_XOR_WriteProcessMemory_9b74 {
  strings:
    $key_9b74 = { cc 06 [2] fe 24 [2] f8 11 [2] d6 11 [2] e9 0d }

  condition:
    any of them
}