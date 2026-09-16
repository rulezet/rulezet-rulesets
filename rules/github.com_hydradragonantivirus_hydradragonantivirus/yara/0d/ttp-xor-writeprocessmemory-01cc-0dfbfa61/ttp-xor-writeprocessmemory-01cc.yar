rule TTP_XOR_WriteProcessMemory_01cc {
  strings:
    $key_01cc = { 56 be [2] 64 9c [2] 62 a9 [2] 4c a9 [2] 73 b5 }

  condition:
    any of them
}