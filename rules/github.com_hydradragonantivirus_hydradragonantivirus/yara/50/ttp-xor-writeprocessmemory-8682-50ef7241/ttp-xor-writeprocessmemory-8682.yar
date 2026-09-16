rule TTP_XOR_WriteProcessMemory_8682 {
  strings:
    $key_8682 = { d1 f0 [2] e3 d2 [2] e5 e7 [2] cb e7 [2] f4 fb }

  condition:
    any of them
}