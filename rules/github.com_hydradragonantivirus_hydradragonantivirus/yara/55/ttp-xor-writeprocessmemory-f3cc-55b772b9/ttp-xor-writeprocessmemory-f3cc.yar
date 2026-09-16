rule TTP_XOR_WriteProcessMemory_f3cc {
  strings:
    $key_f3cc = { a4 be [2] 96 9c [2] 90 a9 [2] be a9 [2] 81 b5 }

  condition:
    any of them
}