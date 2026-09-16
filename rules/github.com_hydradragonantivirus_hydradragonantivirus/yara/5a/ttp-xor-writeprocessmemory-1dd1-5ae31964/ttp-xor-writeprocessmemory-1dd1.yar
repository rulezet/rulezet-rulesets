rule TTP_XOR_WriteProcessMemory_1dd1 {
  strings:
    $key_1dd1 = { 4a a3 [2] 78 81 [2] 7e b4 [2] 50 b4 [2] 6f a8 }

  condition:
    any of them
}