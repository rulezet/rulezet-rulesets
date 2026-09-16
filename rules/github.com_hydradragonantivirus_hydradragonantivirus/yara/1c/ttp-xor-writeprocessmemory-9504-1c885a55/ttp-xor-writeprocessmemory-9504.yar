rule TTP_XOR_WriteProcessMemory_9504 {
  strings:
    $key_9504 = { c2 76 [2] f0 54 [2] f6 61 [2] d8 61 [2] e7 7d }

  condition:
    any of them
}