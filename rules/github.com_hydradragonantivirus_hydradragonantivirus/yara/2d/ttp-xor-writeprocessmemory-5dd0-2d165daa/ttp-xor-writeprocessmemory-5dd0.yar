rule TTP_XOR_WriteProcessMemory_5dd0 {
  strings:
    $key_5dd0 = { 0a a2 [2] 38 80 [2] 3e b5 [2] 10 b5 [2] 2f a9 }

  condition:
    any of them
}