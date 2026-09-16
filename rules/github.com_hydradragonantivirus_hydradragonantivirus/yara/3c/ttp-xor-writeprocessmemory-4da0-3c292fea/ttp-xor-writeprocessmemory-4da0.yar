rule TTP_XOR_WriteProcessMemory_4da0 {
  strings:
    $key_4da0 = { 1a d2 [2] 28 f0 [2] 2e c5 [2] 00 c5 [2] 3f d9 }

  condition:
    any of them
}