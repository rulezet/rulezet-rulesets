rule TTP_XOR_WriteProcessMemory_6cc5 {
  strings:
    $key_6cc5 = { 3b b7 [2] 09 95 [2] 0f a0 [2] 21 a0 [2] 1e bc }

  condition:
    any of them
}