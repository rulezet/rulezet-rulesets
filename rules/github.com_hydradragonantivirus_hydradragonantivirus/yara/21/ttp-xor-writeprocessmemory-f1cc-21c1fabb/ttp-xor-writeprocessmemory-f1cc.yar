rule TTP_XOR_WriteProcessMemory_f1cc {
  strings:
    $key_f1cc = { a6 be [2] 94 9c [2] 92 a9 [2] bc a9 [2] 83 b5 }

  condition:
    any of them
}