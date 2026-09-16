rule TTP_XOR_WriteProcessMemory_c2cc {
  strings:
    $key_c2cc = { 95 be [2] a7 9c [2] a1 a9 [2] 8f a9 [2] b0 b5 }

  condition:
    any of them
}