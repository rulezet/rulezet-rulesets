rule TTP_XOR_WriteProcessMemory_58d5 {
  strings:
    $key_58d5 = { 0f a7 [2] 3d 85 [2] 3b b0 [2] 15 b0 [2] 2a ac }

  condition:
    any of them
}