rule TTP_XOR_WriteProcessMemory_91b1 {
  strings:
    $key_91b1 = { c6 c3 [2] f4 e1 [2] f2 d4 [2] dc d4 [2] e3 c8 }

  condition:
    any of them
}