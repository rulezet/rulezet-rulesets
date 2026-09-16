rule TTP_XOR_WriteProcessMemory_68d4 {
  strings:
    $key_68d4 = { 3f a6 [2] 0d 84 [2] 0b b1 [2] 25 b1 [2] 1a ad }

  condition:
    any of them
}