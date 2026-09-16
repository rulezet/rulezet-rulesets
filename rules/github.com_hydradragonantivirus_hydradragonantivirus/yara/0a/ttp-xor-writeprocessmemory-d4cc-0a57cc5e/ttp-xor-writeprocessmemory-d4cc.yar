rule TTP_XOR_WriteProcessMemory_d4cc {
  strings:
    $key_d4cc = { 83 be [2] b1 9c [2] b7 a9 [2] 99 a9 [2] a6 b5 }

  condition:
    any of them
}