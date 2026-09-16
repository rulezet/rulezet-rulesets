rule TTP_XOR_WriteProcessMemory_3fb0 {
  strings:
    $key_3fb0 = { 68 c2 [2] 5a e0 [2] 5c d5 [2] 72 d5 [2] 4d c9 }

  condition:
    any of them
}