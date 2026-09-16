rule TTP_XOR_WriteProcessMemory_d5cc {
  strings:
    $key_d5cc = { 82 be [2] b0 9c [2] b6 a9 [2] 98 a9 [2] a7 b5 }

  condition:
    any of them
}