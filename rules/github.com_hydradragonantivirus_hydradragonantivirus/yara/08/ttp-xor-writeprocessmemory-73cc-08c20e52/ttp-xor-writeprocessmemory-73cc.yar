rule TTP_XOR_WriteProcessMemory_73cc {
  strings:
    $key_73cc = { 24 be [2] 16 9c [2] 10 a9 [2] 3e a9 [2] 01 b5 }

  condition:
    any of them
}