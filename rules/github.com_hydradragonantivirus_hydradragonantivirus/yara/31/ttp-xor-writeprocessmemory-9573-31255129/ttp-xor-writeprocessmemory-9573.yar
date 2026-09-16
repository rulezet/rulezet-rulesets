rule TTP_XOR_WriteProcessMemory_9573 {
  strings:
    $key_9573 = { c2 01 [2] f0 23 [2] f6 16 [2] d8 16 [2] e7 0a }

  condition:
    any of them
}