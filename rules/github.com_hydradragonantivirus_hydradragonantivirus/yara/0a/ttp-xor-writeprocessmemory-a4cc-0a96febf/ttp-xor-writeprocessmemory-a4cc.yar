rule TTP_XOR_WriteProcessMemory_a4cc {
  strings:
    $key_a4cc = { f3 be [2] c1 9c [2] c7 a9 [2] e9 a9 [2] d6 b5 }

  condition:
    any of them
}