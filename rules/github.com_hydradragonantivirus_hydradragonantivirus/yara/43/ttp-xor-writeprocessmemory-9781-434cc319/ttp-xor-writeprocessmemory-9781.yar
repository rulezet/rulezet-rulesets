rule TTP_XOR_WriteProcessMemory_9781 {
  strings:
    $key_9781 = { c0 f3 [2] f2 d1 [2] f4 e4 [2] da e4 [2] e5 f8 }

  condition:
    any of them
}