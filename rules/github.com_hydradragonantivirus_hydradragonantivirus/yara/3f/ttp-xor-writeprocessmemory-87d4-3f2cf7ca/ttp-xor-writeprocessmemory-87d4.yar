rule TTP_XOR_WriteProcessMemory_87d4 {
  strings:
    $key_87d4 = { d0 a6 [2] e2 84 [2] e4 b1 [2] ca b1 [2] f5 ad }

  condition:
    any of them
}