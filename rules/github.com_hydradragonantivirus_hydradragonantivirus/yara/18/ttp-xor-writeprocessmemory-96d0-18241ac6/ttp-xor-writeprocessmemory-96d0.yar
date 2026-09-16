rule TTP_XOR_WriteProcessMemory_96d0 {
  strings:
    $key_96d0 = { c1 a2 [2] f3 80 [2] f5 b5 [2] db b5 [2] e4 a9 }

  condition:
    any of them
}