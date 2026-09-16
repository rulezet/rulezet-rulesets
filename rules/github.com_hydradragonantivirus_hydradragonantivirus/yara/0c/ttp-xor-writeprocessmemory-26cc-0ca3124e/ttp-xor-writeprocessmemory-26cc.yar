rule TTP_XOR_WriteProcessMemory_26cc {
  strings:
    $key_26cc = { 71 be [2] 43 9c [2] 45 a9 [2] 6b a9 [2] 54 b5 }

  condition:
    any of them
}