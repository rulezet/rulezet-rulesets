rule TTP_XOR_WriteProcessMemory_8440 {
  strings:
    $key_8440 = { d3 32 [2] e1 10 [2] e7 25 [2] c9 25 [2] f6 39 }

  condition:
    any of them
}