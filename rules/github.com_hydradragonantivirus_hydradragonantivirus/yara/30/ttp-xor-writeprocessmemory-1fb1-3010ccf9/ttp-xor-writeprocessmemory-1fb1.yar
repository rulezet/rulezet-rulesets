rule TTP_XOR_WriteProcessMemory_1fb1 {
  strings:
    $key_1fb1 = { 48 c3 [2] 7a e1 [2] 7c d4 [2] 52 d4 [2] 6d c8 }

  condition:
    any of them
}