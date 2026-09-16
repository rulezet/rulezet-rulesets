rule TTP_XOR_WriteProcessMemory_83c2 {
  strings:
    $key_83c2 = { d4 b0 [2] e6 92 [2] e0 a7 [2] ce a7 [2] f1 bb }

  condition:
    any of them
}