rule TTP_XOR_WriteProcessMemory_84f3 {
  strings:
    $key_84f3 = { d3 81 [2] e1 a3 [2] e7 96 [2] c9 96 [2] f6 8a }

  condition:
    any of them
}