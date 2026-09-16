rule TTP_XOR_WriteProcessMemory_87e1 {
  strings:
    $key_87e1 = { d0 93 [2] e2 b1 [2] e4 84 [2] ca 84 [2] f5 98 }

  condition:
    any of them
}