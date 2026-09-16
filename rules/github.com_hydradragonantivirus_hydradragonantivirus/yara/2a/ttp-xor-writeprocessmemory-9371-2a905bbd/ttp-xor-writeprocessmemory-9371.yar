rule TTP_XOR_WriteProcessMemory_9371 {
  strings:
    $key_9371 = { c4 03 [2] f6 21 [2] f0 14 [2] de 14 [2] e1 08 }

  condition:
    any of them
}