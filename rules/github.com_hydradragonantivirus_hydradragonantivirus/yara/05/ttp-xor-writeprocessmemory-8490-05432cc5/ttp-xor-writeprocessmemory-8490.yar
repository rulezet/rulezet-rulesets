rule TTP_XOR_WriteProcessMemory_8490 {
  strings:
    $key_8490 = { d3 e2 [2] e1 c0 [2] e7 f5 [2] c9 f5 [2] f6 e9 }

  condition:
    any of them
}