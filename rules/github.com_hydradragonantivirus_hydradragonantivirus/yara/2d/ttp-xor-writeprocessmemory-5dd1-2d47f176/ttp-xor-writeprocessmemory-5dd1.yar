rule TTP_XOR_WriteProcessMemory_5dd1 {
  strings:
    $key_5dd1 = { 0a a3 [2] 38 81 [2] 3e b4 [2] 10 b4 [2] 2f a8 }

  condition:
    any of them
}