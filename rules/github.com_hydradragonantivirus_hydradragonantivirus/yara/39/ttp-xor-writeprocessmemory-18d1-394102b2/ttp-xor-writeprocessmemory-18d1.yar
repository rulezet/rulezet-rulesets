rule TTP_XOR_WriteProcessMemory_18d1 {
  strings:
    $key_18d1 = { 4f a3 [2] 7d 81 [2] 7b b4 [2] 55 b4 [2] 6a a8 }

  condition:
    any of them
}