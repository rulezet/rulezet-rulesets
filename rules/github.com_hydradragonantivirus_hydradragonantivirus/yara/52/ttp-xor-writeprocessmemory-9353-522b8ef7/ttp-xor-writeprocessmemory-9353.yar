rule TTP_XOR_WriteProcessMemory_9353 {
  strings:
    $key_9353 = { c4 21 [2] f6 03 [2] f0 36 [2] de 36 [2] e1 2a }

  condition:
    any of them
}