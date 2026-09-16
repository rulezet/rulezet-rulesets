rule TTP_XOR_WriteProcessMemory_f6a6 {
  strings:
    $key_f6a6 = { a1 d4 [2] 93 f6 [2] 95 c3 [2] bb c3 [2] 84 df }

  condition:
    any of them
}