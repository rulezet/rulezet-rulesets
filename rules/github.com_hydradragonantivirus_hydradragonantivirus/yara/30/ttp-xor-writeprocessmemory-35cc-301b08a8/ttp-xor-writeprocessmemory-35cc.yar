rule TTP_XOR_WriteProcessMemory_35cc {
  strings:
    $key_35cc = { 62 be [2] 50 9c [2] 56 a9 [2] 78 a9 [2] 47 b5 }

  condition:
    any of them
}