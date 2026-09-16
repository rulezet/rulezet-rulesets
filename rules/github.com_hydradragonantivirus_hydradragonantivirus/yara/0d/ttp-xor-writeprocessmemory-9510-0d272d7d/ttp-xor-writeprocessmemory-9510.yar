rule TTP_XOR_WriteProcessMemory_9510 {
  strings:
    $key_9510 = { c2 62 [2] f0 40 [2] f6 75 [2] d8 75 [2] e7 69 }

  condition:
    any of them
}