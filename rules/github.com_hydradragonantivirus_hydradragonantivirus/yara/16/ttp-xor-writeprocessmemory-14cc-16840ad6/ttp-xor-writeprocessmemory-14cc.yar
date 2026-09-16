rule TTP_XOR_WriteProcessMemory_14cc {
  strings:
    $key_14cc = { 43 be [2] 71 9c [2] 77 a9 [2] 59 a9 [2] 66 b5 }

  condition:
    any of them
}