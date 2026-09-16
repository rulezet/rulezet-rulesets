rule TTP_XOR_WriteProcessMemory_8414 {
  strings:
    $key_8414 = { d3 66 [2] e1 44 [2] e7 71 [2] c9 71 [2] f6 6d }

  condition:
    any of them
}