rule TTP_XOR_WriteProcessMemory_f6f7 {
  strings:
    $key_f6f7 = { a1 85 [2] 93 a7 [2] 95 92 [2] bb 92 [2] 84 8e }

  condition:
    any of them
}