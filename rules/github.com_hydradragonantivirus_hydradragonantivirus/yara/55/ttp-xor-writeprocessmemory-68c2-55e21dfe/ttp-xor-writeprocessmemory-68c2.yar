rule TTP_XOR_WriteProcessMemory_68c2 {
  strings:
    $key_68c2 = { 3f b0 [2] 0d 92 [2] 0b a7 [2] 25 a7 [2] 1a bb }

  condition:
    any of them
}