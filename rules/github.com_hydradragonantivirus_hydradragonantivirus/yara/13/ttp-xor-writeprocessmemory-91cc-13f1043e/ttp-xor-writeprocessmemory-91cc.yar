rule TTP_XOR_WriteProcessMemory_91cc {
  strings:
    $key_91cc = { c6 be [2] f4 9c [2] f2 a9 [2] dc a9 [2] e3 b5 }

  condition:
    any of them
}