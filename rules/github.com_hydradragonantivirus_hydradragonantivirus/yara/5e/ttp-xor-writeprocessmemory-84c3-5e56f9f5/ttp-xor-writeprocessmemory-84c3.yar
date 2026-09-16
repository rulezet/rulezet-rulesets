rule TTP_XOR_WriteProcessMemory_84c3 {
  strings:
    $key_84c3 = { d3 b1 [2] e1 93 [2] e7 a6 [2] c9 a6 [2] f6 ba }

  condition:
    any of them
}