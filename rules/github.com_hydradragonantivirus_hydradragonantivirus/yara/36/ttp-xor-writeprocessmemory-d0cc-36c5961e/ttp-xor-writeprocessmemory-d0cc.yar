rule TTP_XOR_WriteProcessMemory_d0cc {
  strings:
    $key_d0cc = { 87 be [2] b5 9c [2] b3 a9 [2] 9d a9 [2] a2 b5 }

  condition:
    any of them
}