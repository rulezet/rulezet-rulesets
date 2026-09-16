rule TTP_XOR_WriteProcessMemory_15cc {
  strings:
    $key_15cc = { 42 be [2] 70 9c [2] 76 a9 [2] 58 a9 [2] 67 b5 }

  condition:
    any of them
}