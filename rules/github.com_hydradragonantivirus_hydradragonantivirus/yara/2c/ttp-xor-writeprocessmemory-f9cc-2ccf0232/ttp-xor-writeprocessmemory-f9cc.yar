rule TTP_XOR_WriteProcessMemory_f9cc {
  strings:
    $key_f9cc = { ae be [2] 9c 9c [2] 9a a9 [2] b4 a9 [2] 8b b5 }

  condition:
    any of them
}