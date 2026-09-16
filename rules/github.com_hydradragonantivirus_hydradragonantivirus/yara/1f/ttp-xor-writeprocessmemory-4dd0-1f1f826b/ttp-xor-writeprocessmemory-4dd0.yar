rule TTP_XOR_WriteProcessMemory_4dd0 {
  strings:
    $key_4dd0 = { 1a a2 [2] 28 80 [2] 2e b5 [2] 00 b5 [2] 3f a9 }

  condition:
    any of them
}