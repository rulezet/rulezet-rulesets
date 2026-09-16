rule TTP_XOR_WriteProcessMemory_58d4 {
  strings:
    $key_58d4 = { 0f a6 [2] 3d 84 [2] 3b b1 [2] 15 b1 [2] 2a ad }

  condition:
    any of them
}