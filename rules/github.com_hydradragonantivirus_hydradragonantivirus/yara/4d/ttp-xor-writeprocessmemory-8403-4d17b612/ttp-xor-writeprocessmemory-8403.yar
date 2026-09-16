rule TTP_XOR_WriteProcessMemory_8403 {
  strings:
    $key_8403 = { d3 71 [2] e1 53 [2] e7 66 [2] c9 66 [2] f6 7a }

  condition:
    any of them
}