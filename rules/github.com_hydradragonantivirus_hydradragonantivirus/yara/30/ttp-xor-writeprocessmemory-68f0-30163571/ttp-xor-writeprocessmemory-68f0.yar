rule TTP_XOR_WriteProcessMemory_68f0 {
  strings:
    $key_68f0 = { 3f 82 [2] 0d a0 [2] 0b 95 [2] 25 95 [2] 1a 89 }

  condition:
    any of them
}