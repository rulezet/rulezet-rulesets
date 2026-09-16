rule TTP_XOR_WriteProcessMemory_85e7 {
  strings:
    $key_85e7 = { d2 95 [2] e0 b7 [2] e6 82 [2] c8 82 [2] f7 9e }

  condition:
    any of them
}