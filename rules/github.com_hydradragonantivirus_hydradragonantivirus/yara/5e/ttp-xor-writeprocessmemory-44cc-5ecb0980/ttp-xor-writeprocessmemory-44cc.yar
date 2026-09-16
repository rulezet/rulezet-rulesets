rule TTP_XOR_WriteProcessMemory_44cc {
  strings:
    $key_44cc = { 13 be [2] 21 9c [2] 27 a9 [2] 09 a9 [2] 36 b5 }

  condition:
    any of them
}