rule TTP_XOR_WriteProcessMemory_57d0 {
  strings:
    $key_57d0 = { 00 a2 [2] 32 80 [2] 34 b5 [2] 1a b5 [2] 25 a9 }

  condition:
    any of them
}