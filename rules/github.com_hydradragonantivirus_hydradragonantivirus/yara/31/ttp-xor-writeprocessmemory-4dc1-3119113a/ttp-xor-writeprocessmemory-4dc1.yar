rule TTP_XOR_WriteProcessMemory_4dc1 {
  strings:
    $key_4dc1 = { 1a b3 [2] 28 91 [2] 2e a4 [2] 00 a4 [2] 3f b8 }

  condition:
    any of them
}