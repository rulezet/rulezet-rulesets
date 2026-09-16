rule TTP_XOR_WriteProcessMemory_87d1 {
  strings:
    $key_87d1 = { d0 a3 [2] e2 81 [2] e4 b4 [2] ca b4 [2] f5 a8 }

  condition:
    any of them
}