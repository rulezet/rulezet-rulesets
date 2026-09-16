rule TTP_XOR_WriteProcessMemory_9300 {
  strings:
    $key_9300 = { c4 72 [2] f6 50 [2] f0 65 [2] de 65 [2] e1 79 }

  condition:
    any of them
}