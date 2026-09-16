rule TTP_XOR_WriteProcessMemory_78d5 {
  strings:
    $key_78d5 = { 2f a7 [2] 1d 85 [2] 1b b0 [2] 35 b0 [2] 0a ac }

  condition:
    any of them
}