rule TTP_XOR_WriteProcessMemory_18d2 {
  strings:
    $key_18d2 = { 4f a0 [2] 7d 82 [2] 7b b7 [2] 55 b7 [2] 6a ab }

  condition:
    any of them
}