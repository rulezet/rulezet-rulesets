rule TTP_XOR_WriteProcessMemory_f0cc {
  strings:
    $key_f0cc = { a7 be [2] 95 9c [2] 93 a9 [2] bd a9 [2] 82 b5 }

  condition:
    any of them
}