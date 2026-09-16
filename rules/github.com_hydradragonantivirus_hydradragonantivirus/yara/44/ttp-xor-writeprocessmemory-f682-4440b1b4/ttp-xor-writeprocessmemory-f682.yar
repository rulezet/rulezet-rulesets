rule TTP_XOR_WriteProcessMemory_f682 {
  strings:
    $key_f682 = { a1 f0 [2] 93 d2 [2] 95 e7 [2] bb e7 [2] 84 fb }

  condition:
    any of them
}