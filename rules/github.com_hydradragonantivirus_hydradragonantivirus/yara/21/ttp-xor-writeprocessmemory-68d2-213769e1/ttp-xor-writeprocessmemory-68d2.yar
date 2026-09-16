rule TTP_XOR_WriteProcessMemory_68d2 {
  strings:
    $key_68d2 = { 3f a0 [2] 0d 82 [2] 0b b7 [2] 25 b7 [2] 1a ab }

  condition:
    any of them
}