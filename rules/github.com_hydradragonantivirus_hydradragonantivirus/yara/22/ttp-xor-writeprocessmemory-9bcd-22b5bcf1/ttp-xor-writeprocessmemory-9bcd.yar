rule TTP_XOR_WriteProcessMemory_9bcd {
  strings:
    $key_9bcd = { cc bf [2] fe 9d [2] f8 a8 [2] d6 a8 [2] e9 b4 }

  condition:
    any of them
}