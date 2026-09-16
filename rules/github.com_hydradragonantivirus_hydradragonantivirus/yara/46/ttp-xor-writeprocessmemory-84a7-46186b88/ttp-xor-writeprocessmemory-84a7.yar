rule TTP_XOR_WriteProcessMemory_84a7 {
  strings:
    $key_84a7 = { d3 d5 [2] e1 f7 [2] e7 c2 [2] c9 c2 [2] f6 de }

  condition:
    any of them
}