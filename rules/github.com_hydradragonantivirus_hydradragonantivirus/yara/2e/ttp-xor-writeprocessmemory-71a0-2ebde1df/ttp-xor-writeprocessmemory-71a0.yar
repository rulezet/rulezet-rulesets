rule TTP_XOR_WriteProcessMemory_71a0 {
  strings:
    $key_71a0 = { 26 d2 [2] 14 f0 [2] 12 c5 [2] 3c c5 [2] 03 d9 }

  condition:
    any of them
}