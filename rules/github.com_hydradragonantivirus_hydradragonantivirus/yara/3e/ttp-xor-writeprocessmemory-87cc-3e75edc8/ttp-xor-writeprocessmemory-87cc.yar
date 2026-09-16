rule TTP_XOR_WriteProcessMemory_87cc {
  strings:
    $key_87cc = { d0 be [2] e2 9c [2] e4 a9 [2] ca a9 [2] f5 b5 }

  condition:
    any of them
}