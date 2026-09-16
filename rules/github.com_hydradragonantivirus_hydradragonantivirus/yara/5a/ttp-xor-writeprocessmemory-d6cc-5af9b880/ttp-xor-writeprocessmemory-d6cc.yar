rule TTP_XOR_WriteProcessMemory_d6cc {
  strings:
    $key_d6cc = { 81 be [2] b3 9c [2] b5 a9 [2] 9b a9 [2] a4 b5 }

  condition:
    any of them
}