rule TTP_XOR_WriteProcessMemory_48d2 {
  strings:
    $key_48d2 = { 1f a0 [2] 2d 82 [2] 2b b7 [2] 05 b7 [2] 3a ab }

  condition:
    any of them
}