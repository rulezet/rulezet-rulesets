rule TTP_XOR_WriteProcessMemory_84e8 {
  strings:
    $key_84e8 = { d3 9a [2] e1 b8 [2] e7 8d [2] c9 8d [2] f6 91 }

  condition:
    any of them
}