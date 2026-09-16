rule TTP_XOR_WriteProcessMemory_07c0 {
  strings:
    $key_07c0 = { 50 b2 [2] 62 90 [2] 64 a5 [2] 4a a5 [2] 75 b9 }

  condition:
    any of them
}