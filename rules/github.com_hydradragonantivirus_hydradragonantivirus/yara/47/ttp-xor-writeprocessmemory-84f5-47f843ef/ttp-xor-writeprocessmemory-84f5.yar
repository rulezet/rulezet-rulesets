rule TTP_XOR_WriteProcessMemory_84f5 {
  strings:
    $key_84f5 = { d3 87 [2] e1 a5 [2] e7 90 [2] c9 90 [2] f6 8c }

  condition:
    any of them
}