rule TTP_XOR_WriteProcessMemory_22c3 {
  strings:
    $key_22c3 = { 75 b1 [2] 47 93 [2] 41 a6 [2] 6f a6 [2] 50 ba }

  condition:
    any of them
}