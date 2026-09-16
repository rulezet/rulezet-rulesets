rule TTP_XOR_WriteProcessMemory_42c1 {
  strings:
    $key_42c1 = { 15 b3 [2] 27 91 [2] 21 a4 [2] 0f a4 [2] 30 b8 }

  condition:
    any of them
}