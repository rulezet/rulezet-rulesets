rule TTP_XOR_WriteProcessMemory_7fb1 {
  strings:
    $key_7fb1 = { 28 c3 [2] 1a e1 [2] 1c d4 [2] 32 d4 [2] 0d c8 }

  condition:
    any of them
}