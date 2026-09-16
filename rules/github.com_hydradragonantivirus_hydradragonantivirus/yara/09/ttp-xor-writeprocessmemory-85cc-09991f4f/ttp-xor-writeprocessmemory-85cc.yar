rule TTP_XOR_WriteProcessMemory_85cc {
  strings:
    $key_85cc = { d2 be [2] e0 9c [2] e6 a9 [2] c8 a9 [2] f7 b5 }

  condition:
    any of them
}