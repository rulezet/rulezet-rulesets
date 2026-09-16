rule TTP_XOR_WriteProcessMemory_68c1 {
  strings:
    $key_68c1 = { 3f b3 [2] 0d 91 [2] 0b a4 [2] 25 a4 [2] 1a b8 }

  condition:
    any of them
}