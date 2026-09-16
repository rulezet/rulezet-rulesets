rule TTP_XOR_WriteProcessMemory_81cc {
  strings:
    $key_81cc = { d6 be [2] e4 9c [2] e2 a9 [2] cc a9 [2] f3 b5 }

  condition:
    any of them
}