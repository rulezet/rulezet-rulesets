rule TTP_XOR_WriteProcessMemory_62cc {
  strings:
    $key_62cc = { 35 be [2] 07 9c [2] 01 a9 [2] 2f a9 [2] 10 b5 }

  condition:
    any of them
}