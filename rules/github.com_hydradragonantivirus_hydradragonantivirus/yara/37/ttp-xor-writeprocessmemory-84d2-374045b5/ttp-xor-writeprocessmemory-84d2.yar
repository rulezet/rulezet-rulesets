rule TTP_XOR_WriteProcessMemory_84d2 {
  strings:
    $key_84d2 = { d3 a0 [2] e1 82 [2] e7 b7 [2] c9 b7 [2] f6 ab }

  condition:
    any of them
}