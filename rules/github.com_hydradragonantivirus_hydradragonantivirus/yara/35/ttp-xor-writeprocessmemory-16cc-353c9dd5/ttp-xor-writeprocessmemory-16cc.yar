rule TTP_XOR_WriteProcessMemory_16cc {
  strings:
    $key_16cc = { 41 be [2] 73 9c [2] 75 a9 [2] 5b a9 [2] 64 b5 }

  condition:
    any of them
}