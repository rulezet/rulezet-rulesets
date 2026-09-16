rule TTP_XOR_WriteProcessMemory_84f2 {
  strings:
    $key_84f2 = { d3 80 [2] e1 a2 [2] e7 97 [2] c9 97 [2] f6 8b }

  condition:
    any of them
}