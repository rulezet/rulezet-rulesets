rule TTP_XOR_WriteProcessMemory_96d4 {
  strings:
    $key_96d4 = { c1 a6 [2] f3 84 [2] f5 b1 [2] db b1 [2] e4 ad }

  condition:
    any of them
}