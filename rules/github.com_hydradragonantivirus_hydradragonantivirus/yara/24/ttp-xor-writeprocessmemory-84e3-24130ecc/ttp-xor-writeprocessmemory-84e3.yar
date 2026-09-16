rule TTP_XOR_WriteProcessMemory_84e3 {
  strings:
    $key_84e3 = { d3 91 [2] e1 b3 [2] e7 86 [2] c9 86 [2] f6 9a }

  condition:
    any of them
}