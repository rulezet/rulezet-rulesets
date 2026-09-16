rule TTP_XOR_WriteProcessMemory_9361 {
  strings:
    $key_9361 = { c4 13 [2] f6 31 [2] f0 04 [2] de 04 [2] e1 18 }

  condition:
    any of them
}