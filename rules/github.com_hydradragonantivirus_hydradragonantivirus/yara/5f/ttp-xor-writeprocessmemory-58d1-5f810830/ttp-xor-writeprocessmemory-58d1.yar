rule TTP_XOR_WriteProcessMemory_58d1 {
  strings:
    $key_58d1 = { 0f a3 [2] 3d 81 [2] 3b b4 [2] 15 b4 [2] 2a a8 }

  condition:
    any of them
}