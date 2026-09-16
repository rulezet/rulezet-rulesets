rule TTP_XOR_WriteProcessMemory_a6cc {
  strings:
    $key_a6cc = { f1 be [2] c3 9c [2] c5 a9 [2] eb a9 [2] d4 b5 }

  condition:
    any of them
}