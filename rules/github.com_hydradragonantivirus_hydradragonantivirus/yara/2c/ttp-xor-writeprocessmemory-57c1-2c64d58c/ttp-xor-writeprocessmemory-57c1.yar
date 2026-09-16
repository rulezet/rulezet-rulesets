rule TTP_XOR_WriteProcessMemory_57c1 {
  strings:
    $key_57c1 = { 00 b3 [2] 32 91 [2] 34 a4 [2] 1a a4 [2] 25 b8 }

  condition:
    any of them
}