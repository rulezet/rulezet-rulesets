rule TTP_XOR_WriteProcessMemory_22c4 {
  strings:
    $key_22c4 = { 75 b6 [2] 47 94 [2] 41 a1 [2] 6f a1 [2] 50 bd }

  condition:
    any of them
}