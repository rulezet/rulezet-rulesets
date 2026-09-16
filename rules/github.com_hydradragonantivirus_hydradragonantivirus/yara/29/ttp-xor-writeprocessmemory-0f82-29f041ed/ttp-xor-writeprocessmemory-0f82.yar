rule TTP_XOR_WriteProcessMemory_0f82 {
  strings:
    $key_0f82 = { 58 f0 [2] 6a d2 [2] 6c e7 [2] 42 e7 [2] 7d fb }

  condition:
    any of them
}