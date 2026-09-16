rule TTP_XOR_WriteProcessMemory_f6e0 {
  strings:
    $key_f6e0 = { a1 92 [2] 93 b0 [2] 95 85 [2] bb 85 [2] 84 99 }

  condition:
    any of them
}