rule TTP_XOR_WriteProcessMemory_8453 {
  strings:
    $key_8453 = { d3 21 [2] e1 03 [2] e7 36 [2] c9 36 [2] f6 2a }

  condition:
    any of them
}