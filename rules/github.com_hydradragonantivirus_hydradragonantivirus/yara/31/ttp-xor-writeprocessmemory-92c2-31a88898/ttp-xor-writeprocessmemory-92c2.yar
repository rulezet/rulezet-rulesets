rule TTP_XOR_WriteProcessMemory_92c2 {
  strings:
    $key_92c2 = { c5 b0 [2] f7 92 [2] f1 a7 [2] df a7 [2] e0 bb }

  condition:
    any of them
}