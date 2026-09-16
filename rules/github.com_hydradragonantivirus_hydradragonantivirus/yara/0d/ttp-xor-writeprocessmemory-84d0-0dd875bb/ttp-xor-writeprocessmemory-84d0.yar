rule TTP_XOR_WriteProcessMemory_84d0 {
  strings:
    $key_84d0 = { d3 a2 [2] e1 80 [2] e7 b5 [2] c9 b5 [2] f6 a9 }

  condition:
    any of them
}