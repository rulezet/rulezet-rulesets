rule TTP_XOR_WriteProcessMemory_84e5 {
  strings:
    $key_84e5 = { d3 97 [2] e1 b5 [2] e7 80 [2] c9 80 [2] f6 9c }

  condition:
    any of them
}