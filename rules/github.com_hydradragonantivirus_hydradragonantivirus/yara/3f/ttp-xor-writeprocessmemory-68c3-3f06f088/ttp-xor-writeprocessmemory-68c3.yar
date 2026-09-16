rule TTP_XOR_WriteProcessMemory_68c3 {
  strings:
    $key_68c3 = { 3f b1 [2] 0d 93 [2] 0b a6 [2] 25 a6 [2] 1a ba }

  condition:
    any of them
}