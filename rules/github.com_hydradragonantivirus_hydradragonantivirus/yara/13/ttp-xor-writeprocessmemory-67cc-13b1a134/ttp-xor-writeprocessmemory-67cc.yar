rule TTP_XOR_WriteProcessMemory_67cc {
  strings:
    $key_67cc = { 30 be [2] 02 9c [2] 04 a9 [2] 2a a9 [2] 15 b5 }

  condition:
    any of them
}