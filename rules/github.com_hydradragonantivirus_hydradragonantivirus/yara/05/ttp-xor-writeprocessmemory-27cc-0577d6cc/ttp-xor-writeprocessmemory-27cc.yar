rule TTP_XOR_WriteProcessMemory_27cc {
  strings:
    $key_27cc = { 70 be [2] 42 9c [2] 44 a9 [2] 6a a9 [2] 55 b5 }

  condition:
    any of them
}