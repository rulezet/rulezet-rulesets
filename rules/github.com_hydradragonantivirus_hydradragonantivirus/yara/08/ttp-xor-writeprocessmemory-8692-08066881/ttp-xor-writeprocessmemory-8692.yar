rule TTP_XOR_WriteProcessMemory_8692 {
  strings:
    $key_8692 = { d1 e0 [2] e3 c2 [2] e5 f7 [2] cb f7 [2] f4 eb }

  condition:
    any of them
}