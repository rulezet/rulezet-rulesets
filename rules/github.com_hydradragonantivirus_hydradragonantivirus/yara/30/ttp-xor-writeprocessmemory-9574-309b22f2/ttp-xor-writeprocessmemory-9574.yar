rule TTP_XOR_WriteProcessMemory_9574 {
  strings:
    $key_9574 = { c2 06 [2] f0 24 [2] f6 11 [2] d8 11 [2] e7 0d }

  condition:
    any of them
}