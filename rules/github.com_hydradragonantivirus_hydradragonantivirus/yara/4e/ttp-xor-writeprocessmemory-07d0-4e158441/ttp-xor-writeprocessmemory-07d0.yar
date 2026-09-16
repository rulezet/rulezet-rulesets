rule TTP_XOR_WriteProcessMemory_07d0 {
  strings:
    $key_07d0 = { 50 a2 [2] 62 80 [2] 64 b5 [2] 4a b5 [2] 75 a9 }

  condition:
    any of them
}