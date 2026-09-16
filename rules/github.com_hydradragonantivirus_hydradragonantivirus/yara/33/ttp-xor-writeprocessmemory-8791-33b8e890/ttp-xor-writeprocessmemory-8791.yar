rule TTP_XOR_WriteProcessMemory_8791 {
  strings:
    $key_8791 = { d0 e3 [2] e2 c1 [2] e4 f4 [2] ca f4 [2] f5 e8 }

  condition:
    any of them
}