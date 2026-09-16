rule TTP_XOR_WriteProcessMemory_68d6 {
  strings:
    $key_68d6 = { 3f a4 [2] 0d 86 [2] 0b b3 [2] 25 b3 [2] 1a af }

  condition:
    any of them
}