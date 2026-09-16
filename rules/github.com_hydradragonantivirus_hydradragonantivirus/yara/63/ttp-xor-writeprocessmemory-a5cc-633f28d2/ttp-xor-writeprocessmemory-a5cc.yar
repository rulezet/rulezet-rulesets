rule TTP_XOR_WriteProcessMemory_a5cc {
  strings:
    $key_a5cc = { f2 be [2] c0 9c [2] c6 a9 [2] e8 a9 [2] d7 b5 }

  condition:
    any of them
}