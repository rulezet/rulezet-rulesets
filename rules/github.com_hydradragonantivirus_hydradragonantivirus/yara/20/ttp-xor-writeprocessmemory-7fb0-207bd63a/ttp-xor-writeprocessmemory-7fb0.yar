rule TTP_XOR_WriteProcessMemory_7fb0 {
  strings:
    $key_7fb0 = { 28 c2 [2] 1a e0 [2] 1c d5 [2] 32 d5 [2] 0d c9 }

  condition:
    any of them
}