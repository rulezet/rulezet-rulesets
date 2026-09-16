rule TTP_XOR_WriteProcessMemory_9500 {
  strings:
    $key_9500 = { c2 72 [2] f0 50 [2] f6 65 [2] d8 65 [2] e7 79 }

  condition:
    any of them
}