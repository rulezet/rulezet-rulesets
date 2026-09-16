rule TTP_XOR_WriteProcessMemory_8685 {
  strings:
    $key_8685 = { d1 f7 [2] e3 d5 [2] e5 e0 [2] cb e0 [2] f4 fc }

  condition:
    any of them
}