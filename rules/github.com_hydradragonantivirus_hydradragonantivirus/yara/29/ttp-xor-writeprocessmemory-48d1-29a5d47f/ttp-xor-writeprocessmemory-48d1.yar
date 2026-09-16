rule TTP_XOR_WriteProcessMemory_48d1 {
  strings:
    $key_48d1 = { 1f a3 [2] 2d 81 [2] 2b b4 [2] 05 b4 [2] 3a a8 }

  condition:
    any of them
}