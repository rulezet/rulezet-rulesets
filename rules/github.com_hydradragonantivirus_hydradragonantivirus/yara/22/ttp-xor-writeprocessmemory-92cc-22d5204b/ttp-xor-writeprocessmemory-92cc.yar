rule TTP_XOR_WriteProcessMemory_92cc {
  strings:
    $key_92cc = { c5 be [2] f7 9c [2] f1 a9 [2] df a9 [2] e0 b5 }

  condition:
    any of them
}