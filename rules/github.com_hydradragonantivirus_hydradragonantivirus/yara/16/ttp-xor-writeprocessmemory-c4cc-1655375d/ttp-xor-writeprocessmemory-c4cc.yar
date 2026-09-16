rule TTP_XOR_WriteProcessMemory_c4cc {
  strings:
    $key_c4cc = { 93 be [2] a1 9c [2] a7 a9 [2] 89 a9 [2] b6 b5 }

  condition:
    any of them
}