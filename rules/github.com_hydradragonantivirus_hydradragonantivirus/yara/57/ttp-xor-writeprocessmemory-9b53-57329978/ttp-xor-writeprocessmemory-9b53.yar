rule TTP_XOR_WriteProcessMemory_9b53 {
  strings:
    $key_9b53 = { cc 21 [2] fe 03 [2] f8 36 [2] d6 36 [2] e9 2a }

  condition:
    any of them
}