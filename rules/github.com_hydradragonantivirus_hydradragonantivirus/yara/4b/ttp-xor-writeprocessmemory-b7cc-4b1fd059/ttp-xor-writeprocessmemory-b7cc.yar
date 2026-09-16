rule TTP_XOR_WriteProcessMemory_b7cc {
  strings:
    $key_b7cc = { e0 be [2] d2 9c [2] d4 a9 [2] fa a9 [2] c5 b5 }

  condition:
    any of them
}