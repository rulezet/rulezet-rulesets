rule TTP_XOR_WriteProcessMemory_68d7 {
  strings:
    $key_68d7 = { 3f a5 [2] 0d 87 [2] 0b b2 [2] 25 b2 [2] 1a ae }

  condition:
    any of them
}