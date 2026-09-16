rule TTP_XOR_WriteProcessMemory_87e7 {
  strings:
    $key_87e7 = { d0 95 [2] e2 b7 [2] e4 82 [2] ca 82 [2] f5 9e }

  condition:
    any of them
}