rule TTP_XOR_WriteProcessMemory_81c2 {
  strings:
    $key_81c2 = { d6 b0 [2] e4 92 [2] e2 a7 [2] cc a7 [2] f3 bb }

  condition:
    any of them
}