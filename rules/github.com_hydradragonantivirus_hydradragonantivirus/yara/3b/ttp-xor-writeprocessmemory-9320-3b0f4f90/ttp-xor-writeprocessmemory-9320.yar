rule TTP_XOR_WriteProcessMemory_9320 {
  strings:
    $key_9320 = { c4 52 [2] f6 70 [2] f0 45 [2] de 45 [2] e1 59 }

  condition:
    any of them
}