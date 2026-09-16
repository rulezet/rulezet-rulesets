rule TTP_XOR_WriteProcessMemory_e7cc {
  strings:
    $key_e7cc = { b0 be [2] 82 9c [2] 84 a9 [2] aa a9 [2] 95 b5 }

  condition:
    any of them
}