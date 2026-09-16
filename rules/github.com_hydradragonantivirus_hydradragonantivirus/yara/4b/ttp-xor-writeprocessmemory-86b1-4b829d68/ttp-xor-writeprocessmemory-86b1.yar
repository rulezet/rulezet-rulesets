rule TTP_XOR_WriteProcessMemory_86b1 {
  strings:
    $key_86b1 = { d1 c3 [2] e3 e1 [2] e5 d4 [2] cb d4 [2] f4 c8 }

  condition:
    any of them
}