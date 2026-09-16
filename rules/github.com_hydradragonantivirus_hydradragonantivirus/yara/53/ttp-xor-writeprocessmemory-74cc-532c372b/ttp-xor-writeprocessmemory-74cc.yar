rule TTP_XOR_WriteProcessMemory_74cc {
  strings:
    $key_74cc = { 23 be [2] 11 9c [2] 17 a9 [2] 39 a9 [2] 06 b5 }

  condition:
    any of them
}