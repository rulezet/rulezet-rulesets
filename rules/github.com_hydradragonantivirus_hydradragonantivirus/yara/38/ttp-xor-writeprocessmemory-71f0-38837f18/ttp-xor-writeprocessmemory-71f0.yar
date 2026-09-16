rule TTP_XOR_WriteProcessMemory_71f0 {
  strings:
    $key_71f0 = { 26 82 [2] 14 a0 [2] 12 95 [2] 3c 95 [2] 03 89 }

  condition:
    any of them
}