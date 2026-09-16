rule TTP_XOR_WriteProcessMemory_f685 {
  strings:
    $key_f685 = { a1 f7 [2] 93 d5 [2] 95 e0 [2] bb e0 [2] 84 fc }

  condition:
    any of them
}