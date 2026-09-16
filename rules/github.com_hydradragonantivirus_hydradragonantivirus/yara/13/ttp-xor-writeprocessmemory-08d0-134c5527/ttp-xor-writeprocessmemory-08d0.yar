rule TTP_XOR_WriteProcessMemory_08d0 {
  strings:
    $key_08d0 = { 5f a2 [2] 6d 80 [2] 6b b5 [2] 45 b5 [2] 7a a9 }

  condition:
    any of them
}