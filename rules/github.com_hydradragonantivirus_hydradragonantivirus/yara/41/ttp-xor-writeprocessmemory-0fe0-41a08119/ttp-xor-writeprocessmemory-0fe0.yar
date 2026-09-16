rule TTP_XOR_WriteProcessMemory_0fe0 {
  strings:
    $key_0fe0 = { 58 92 [2] 6a b0 [2] 6c 85 [2] 42 85 [2] 7d 99 }

  condition:
    any of them
}