rule TTP_XOR_WriteProcessMemory_08d4 {
  strings:
    $key_08d4 = { 5f a6 [2] 6d 84 [2] 6b b1 [2] 45 b1 [2] 7a ad }

  condition:
    any of them
}