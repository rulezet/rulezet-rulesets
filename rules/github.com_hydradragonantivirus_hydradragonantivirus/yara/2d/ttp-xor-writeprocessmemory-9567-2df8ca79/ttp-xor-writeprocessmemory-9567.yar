rule TTP_XOR_WriteProcessMemory_9567 {
  strings:
    $key_9567 = { c2 15 [2] f0 37 [2] f6 02 [2] d8 02 [2] e7 1e }

  condition:
    any of them
}