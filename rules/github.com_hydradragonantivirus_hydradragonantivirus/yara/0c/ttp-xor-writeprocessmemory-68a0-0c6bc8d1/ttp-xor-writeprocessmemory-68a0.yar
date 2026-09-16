rule TTP_XOR_WriteProcessMemory_68a0 {
  strings:
    $key_68a0 = { 3f d2 [2] 0d f0 [2] 0b c5 [2] 25 c5 [2] 1a d9 }

  condition:
    any of them
}