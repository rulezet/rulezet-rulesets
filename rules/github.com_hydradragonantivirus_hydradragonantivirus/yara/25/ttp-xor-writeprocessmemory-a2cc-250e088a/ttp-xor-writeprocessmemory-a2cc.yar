rule TTP_XOR_WriteProcessMemory_a2cc {
  strings:
    $key_a2cc = { f5 be [2] c7 9c [2] c1 a9 [2] ef a9 [2] d0 b5 }

  condition:
    any of them
}