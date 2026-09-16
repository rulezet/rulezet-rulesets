rule TTP_XOR_WriteProcessMemory_84b0 {
  strings:
    $key_84b0 = { d3 c2 [2] e1 e0 [2] e7 d5 [2] c9 d5 [2] f6 c9 }

  condition:
    any of them
}