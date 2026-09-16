rule TTP_XOR_WriteProcessMemory_8681 {
  strings:
    $key_8681 = { d1 f3 [2] e3 d1 [2] e5 e4 [2] cb e4 [2] f4 f8 }

  condition:
    any of them
}