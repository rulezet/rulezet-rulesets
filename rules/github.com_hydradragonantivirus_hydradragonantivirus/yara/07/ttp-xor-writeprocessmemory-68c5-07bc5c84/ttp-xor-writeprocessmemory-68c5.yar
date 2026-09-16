rule TTP_XOR_WriteProcessMemory_68c5 {
  strings:
    $key_68c5 = { 3f b7 [2] 0d 95 [2] 0b a0 [2] 25 a0 [2] 1a bc }

  condition:
    any of them
}