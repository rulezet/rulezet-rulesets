rule TTP_XOR_WriteProcessMemory_63cc {
  strings:
    $key_63cc = { 34 be [2] 06 9c [2] 00 a9 [2] 2e a9 [2] 11 b5 }

  condition:
    any of them
}