rule TTP_XOR_WriteProcessMemory_68d5 {
  strings:
    $key_68d5 = { 3f a7 [2] 0d 85 [2] 0b b0 [2] 25 b0 [2] 1a ac }

  condition:
    any of them
}