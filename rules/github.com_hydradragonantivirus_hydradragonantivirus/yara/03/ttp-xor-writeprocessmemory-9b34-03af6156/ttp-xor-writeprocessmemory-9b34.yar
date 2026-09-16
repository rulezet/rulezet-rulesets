rule TTP_XOR_WriteProcessMemory_9b34 {
  strings:
    $key_9b34 = { cc 46 [2] fe 64 [2] f8 51 [2] d6 51 [2] e9 4d }

  condition:
    any of them
}