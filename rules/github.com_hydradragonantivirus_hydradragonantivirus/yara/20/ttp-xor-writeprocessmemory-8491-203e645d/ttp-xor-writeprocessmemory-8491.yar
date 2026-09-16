rule TTP_XOR_WriteProcessMemory_8491 {
  strings:
    $key_8491 = { d3 e3 [2] e1 c1 [2] e7 f4 [2] c9 f4 [2] f6 e8 }

  condition:
    any of them
}