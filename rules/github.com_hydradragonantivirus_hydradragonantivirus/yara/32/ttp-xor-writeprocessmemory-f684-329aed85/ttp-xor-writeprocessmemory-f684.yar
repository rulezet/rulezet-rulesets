rule TTP_XOR_WriteProcessMemory_f684 {
  strings:
    $key_f684 = { a1 f6 [2] 93 d4 [2] 95 e1 [2] bb e1 [2] 84 fd }

  condition:
    any of them
}