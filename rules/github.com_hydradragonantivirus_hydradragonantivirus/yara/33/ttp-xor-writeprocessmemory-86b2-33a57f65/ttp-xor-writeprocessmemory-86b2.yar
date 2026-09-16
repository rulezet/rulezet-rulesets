rule TTP_XOR_WriteProcessMemory_86b2 {
  strings:
    $key_86b2 = { d1 c0 [2] e3 e2 [2] e5 d7 [2] cb d7 [2] f4 cb }

  condition:
    any of them
}