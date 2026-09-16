rule TTP_XOR_WriteProcessMemory_18d5 {
  strings:
    $key_18d5 = { 4f a7 [2] 7d 85 [2] 7b b0 [2] 55 b0 [2] 6a ac }

  condition:
    any of them
}