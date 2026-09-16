rule TTP_XOR_WriteProcessMemory_e1cc {
  strings:
    $key_e1cc = { b6 be [2] 84 9c [2] 82 a9 [2] ac a9 [2] 93 b5 }

  condition:
    any of them
}