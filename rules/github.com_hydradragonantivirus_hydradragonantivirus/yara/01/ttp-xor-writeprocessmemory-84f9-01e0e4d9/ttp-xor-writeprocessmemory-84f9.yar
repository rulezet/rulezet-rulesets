rule TTP_XOR_WriteProcessMemory_84f9 {
  strings:
    $key_84f9 = { d3 8b [2] e1 a9 [2] e7 9c [2] c9 9c [2] f6 80 }

  condition:
    any of them
}