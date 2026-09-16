rule TTP_XOR_WriteProcessMemory_5cc5 {
  strings:
    $key_5cc5 = { 0b b7 [2] 39 95 [2] 3f a0 [2] 11 a0 [2] 2e bc }

  condition:
    any of them
}