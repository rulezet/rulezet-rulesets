rule TTP_XOR_WriteProcessMemory_2cc5 {
  strings:
    $key_2cc5 = { 7b b7 [2] 49 95 [2] 4f a0 [2] 61 a0 [2] 5e bc }

  condition:
    any of them
}