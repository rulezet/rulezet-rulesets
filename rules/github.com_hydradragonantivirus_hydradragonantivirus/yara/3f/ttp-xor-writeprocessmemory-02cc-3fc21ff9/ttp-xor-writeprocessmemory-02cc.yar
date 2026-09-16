rule TTP_XOR_WriteProcessMemory_02cc {
  strings:
    $key_02cc = { 55 be [2] 67 9c [2] 61 a9 [2] 4f a9 [2] 70 b5 }

  condition:
    any of them
}