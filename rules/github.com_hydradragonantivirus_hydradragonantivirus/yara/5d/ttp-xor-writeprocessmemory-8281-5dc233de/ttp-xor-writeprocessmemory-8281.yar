rule TTP_XOR_WriteProcessMemory_8281 {
  strings:
    $key_8281 = { d5 f3 [2] e7 d1 [2] e1 e4 [2] cf e4 [2] f0 f8 }

  condition:
    any of them
}