rule TTP_XOR_WriteProcessMemory_31cc {
  strings:
    $key_31cc = { 66 be [2] 54 9c [2] 52 a9 [2] 7c a9 [2] 43 b5 }

  condition:
    any of them
}