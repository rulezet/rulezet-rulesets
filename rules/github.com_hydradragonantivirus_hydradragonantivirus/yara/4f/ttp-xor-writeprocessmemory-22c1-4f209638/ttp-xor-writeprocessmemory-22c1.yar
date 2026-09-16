rule TTP_XOR_WriteProcessMemory_22c1 {
  strings:
    $key_22c1 = { 75 b3 [2] 47 91 [2] 41 a4 [2] 6f a4 [2] 50 b8 }

  condition:
    any of them
}