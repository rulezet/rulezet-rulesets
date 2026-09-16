rule TTP_XOR_WriteProcessMemory_d1cc {
  strings:
    $key_d1cc = { 86 be [2] b4 9c [2] b2 a9 [2] 9c a9 [2] a3 b5 }

  condition:
    any of them
}