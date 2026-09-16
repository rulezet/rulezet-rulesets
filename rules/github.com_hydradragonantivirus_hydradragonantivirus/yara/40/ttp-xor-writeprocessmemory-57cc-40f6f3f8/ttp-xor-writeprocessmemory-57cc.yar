rule TTP_XOR_WriteProcessMemory_57cc {
  strings:
    $key_57cc = { 00 be [2] 32 9c [2] 34 a9 [2] 1a a9 [2] 25 b5 }

  condition:
    any of them
}