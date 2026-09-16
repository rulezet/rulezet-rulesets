rule TTP_XOR_WriteProcessMemory_b3cc {
  strings:
    $key_b3cc = { e4 be [2] d6 9c [2] d0 a9 [2] fe a9 [2] c1 b5 }

  condition:
    any of them
}