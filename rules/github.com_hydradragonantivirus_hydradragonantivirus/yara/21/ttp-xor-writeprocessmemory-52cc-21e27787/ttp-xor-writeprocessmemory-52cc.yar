rule TTP_XOR_WriteProcessMemory_52cc {
  strings:
    $key_52cc = { 05 be [2] 37 9c [2] 31 a9 [2] 1f a9 [2] 20 b5 }

  condition:
    any of them
}