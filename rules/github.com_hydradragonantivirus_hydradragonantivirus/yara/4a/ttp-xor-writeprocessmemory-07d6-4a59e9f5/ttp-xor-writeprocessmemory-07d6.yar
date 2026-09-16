rule TTP_XOR_WriteProcessMemory_07d6 {
  strings:
    $key_07d6 = { 50 a4 [2] 62 86 [2] 64 b3 [2] 4a b3 [2] 75 af }

  condition:
    any of them
}