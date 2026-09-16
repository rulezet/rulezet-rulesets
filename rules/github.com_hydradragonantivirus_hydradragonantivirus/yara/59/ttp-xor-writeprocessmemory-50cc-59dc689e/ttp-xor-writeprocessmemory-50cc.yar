rule TTP_XOR_WriteProcessMemory_50cc {
  strings:
    $key_50cc = { 07 be [2] 35 9c [2] 33 a9 [2] 1d a9 [2] 22 b5 }

  condition:
    any of them
}