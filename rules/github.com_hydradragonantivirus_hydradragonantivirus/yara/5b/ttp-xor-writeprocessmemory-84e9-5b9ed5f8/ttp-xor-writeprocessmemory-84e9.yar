rule TTP_XOR_WriteProcessMemory_84e9 {
  strings:
    $key_84e9 = { d3 9b [2] e1 b9 [2] e7 8c [2] c9 8c [2] f6 90 }

  condition:
    any of them
}