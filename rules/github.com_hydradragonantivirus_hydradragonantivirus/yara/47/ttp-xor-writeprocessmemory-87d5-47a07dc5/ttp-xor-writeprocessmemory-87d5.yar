rule TTP_XOR_WriteProcessMemory_87d5 {
  strings:
    $key_87d5 = { d0 a7 [2] e2 85 [2] e4 b0 [2] ca b0 [2] f5 ac }

  condition:
    any of them
}