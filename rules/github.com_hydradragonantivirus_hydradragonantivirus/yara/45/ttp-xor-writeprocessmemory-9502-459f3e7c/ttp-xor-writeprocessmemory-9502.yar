rule TTP_XOR_WriteProcessMemory_9502 {
  strings:
    $key_9502 = { c2 70 [2] f0 52 [2] f6 67 [2] d8 67 [2] e7 7b }

  condition:
    any of them
}