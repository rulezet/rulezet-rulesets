rule TTP_XOR_WriteProcessMemory_e4cc {
  strings:
    $key_e4cc = { b3 be [2] 81 9c [2] 87 a9 [2] a9 a9 [2] 96 b5 }

  condition:
    any of them
}