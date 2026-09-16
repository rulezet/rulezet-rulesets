rule TTP_XOR_WriteProcessMemory_7dd1 {
  strings:
    $key_7dd1 = { 2a a3 [2] 18 81 [2] 1e b4 [2] 30 b4 [2] 0f a8 }

  condition:
    any of them
}