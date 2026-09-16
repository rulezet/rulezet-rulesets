rule TTP_XOR_WriteProcessMemory_05cc {
  strings:
    $key_05cc = { 52 be [2] 60 9c [2] 66 a9 [2] 48 a9 [2] 77 b5 }

  condition:
    any of them
}