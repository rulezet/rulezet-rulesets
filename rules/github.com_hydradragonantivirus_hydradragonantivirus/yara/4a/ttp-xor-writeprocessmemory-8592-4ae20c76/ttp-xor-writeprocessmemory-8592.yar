rule TTP_XOR_WriteProcessMemory_8592 {
  strings:
    $key_8592 = { d2 e0 [2] e0 c2 [2] e6 f7 [2] c8 f7 [2] f7 eb }

  condition:
    any of them
}