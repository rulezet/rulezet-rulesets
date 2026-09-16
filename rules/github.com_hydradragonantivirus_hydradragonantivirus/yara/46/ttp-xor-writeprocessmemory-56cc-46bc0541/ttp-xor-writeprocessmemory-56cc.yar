rule TTP_XOR_WriteProcessMemory_56cc {
  strings:
    $key_56cc = { 01 be [2] 33 9c [2] 35 a9 [2] 1b a9 [2] 24 b5 }

  condition:
    any of them
}