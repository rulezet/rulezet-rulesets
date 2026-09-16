rule TTP_XOR_WriteProcessMemory_66cc {
  strings:
    $key_66cc = { 31 be [2] 03 9c [2] 05 a9 [2] 2b a9 [2] 14 b5 }

  condition:
    any of them
}