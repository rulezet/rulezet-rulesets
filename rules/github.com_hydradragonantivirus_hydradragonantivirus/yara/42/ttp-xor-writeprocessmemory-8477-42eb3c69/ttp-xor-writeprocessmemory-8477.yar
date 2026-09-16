rule TTP_XOR_WriteProcessMemory_8477 {
  strings:
    $key_8477 = { d3 05 [2] e1 27 [2] e7 12 [2] c9 12 [2] f6 0e }

  condition:
    any of them
}