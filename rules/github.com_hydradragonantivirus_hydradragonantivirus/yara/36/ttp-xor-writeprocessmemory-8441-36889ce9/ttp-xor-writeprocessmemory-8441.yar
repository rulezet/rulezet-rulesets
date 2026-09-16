rule TTP_XOR_WriteProcessMemory_8441 {
  strings:
    $key_8441 = { d3 33 [2] e1 11 [2] e7 24 [2] c9 24 [2] f6 38 }

  condition:
    any of them
}