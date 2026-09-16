rule TTP_XOR_WriteProcessMemory_8492 {
  strings:
    $key_8492 = { d3 e0 [2] e1 c2 [2] e7 f7 [2] c9 f7 [2] f6 eb }

  condition:
    any of them
}