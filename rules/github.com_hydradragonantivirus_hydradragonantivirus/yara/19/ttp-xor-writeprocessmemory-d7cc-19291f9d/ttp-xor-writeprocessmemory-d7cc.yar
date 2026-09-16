rule TTP_XOR_WriteProcessMemory_d7cc {
  strings:
    $key_d7cc = { 80 be [2] b2 9c [2] b4 a9 [2] 9a a9 [2] a5 b5 }

  condition:
    any of them
}