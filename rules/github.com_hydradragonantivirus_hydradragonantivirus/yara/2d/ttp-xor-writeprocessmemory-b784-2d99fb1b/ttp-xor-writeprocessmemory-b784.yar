rule TTP_XOR_WriteProcessMemory_b784 {
  strings:
    $key_b784 = { e0 f6 [2] d2 d4 [2] d4 e1 [2] fa e1 [2] c5 fd }

  condition:
    any of them
}