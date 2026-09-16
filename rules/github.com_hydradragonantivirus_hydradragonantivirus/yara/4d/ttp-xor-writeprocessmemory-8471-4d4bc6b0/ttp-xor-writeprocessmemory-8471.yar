rule TTP_XOR_WriteProcessMemory_8471 {
  strings:
    $key_8471 = { d3 03 [2] e1 21 [2] e7 14 [2] c9 14 [2] f6 08 }

  condition:
    any of them
}