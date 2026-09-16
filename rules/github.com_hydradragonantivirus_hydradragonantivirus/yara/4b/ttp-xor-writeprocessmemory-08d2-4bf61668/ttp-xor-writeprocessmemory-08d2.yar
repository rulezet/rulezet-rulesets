rule TTP_XOR_WriteProcessMemory_08d2 {
  strings:
    $key_08d2 = { 5f a0 [2] 6d 82 [2] 6b b7 [2] 45 b7 [2] 7a ab }

  condition:
    any of them
}