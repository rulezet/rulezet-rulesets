rule TTP_XOR_WriteProcessMemory_3fb1 {
  strings:
    $key_3fb1 = { 68 c3 [2] 5a e1 [2] 5c d4 [2] 72 d4 [2] 4d c8 }

  condition:
    any of them
}