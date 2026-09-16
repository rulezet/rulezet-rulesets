rule TTP_XOR_WriteProcessMemory_37cc {
  strings:
    $key_37cc = { 60 be [2] 52 9c [2] 54 a9 [2] 7a a9 [2] 45 b5 }

  condition:
    any of them
}