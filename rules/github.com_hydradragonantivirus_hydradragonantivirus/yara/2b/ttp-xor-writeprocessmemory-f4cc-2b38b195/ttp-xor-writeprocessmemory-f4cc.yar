rule TTP_XOR_WriteProcessMemory_f4cc {
  strings:
    $key_f4cc = { a3 be [2] 91 9c [2] 97 a9 [2] b9 a9 [2] 86 b5 }

  condition:
    any of them
}