rule TTP_XOR_WriteProcessMemory_f681 {
  strings:
    $key_f681 = { a1 f3 [2] 93 d1 [2] 95 e4 [2] bb e4 [2] 84 f8 }

  condition:
    any of them
}