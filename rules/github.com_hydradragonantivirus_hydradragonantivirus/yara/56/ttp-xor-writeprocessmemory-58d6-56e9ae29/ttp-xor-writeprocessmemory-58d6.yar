rule TTP_XOR_WriteProcessMemory_58d6 {
  strings:
    $key_58d6 = { 0f a4 [2] 3d 86 [2] 3b b3 [2] 15 b3 [2] 2a af }

  condition:
    any of them
}