rule TTP_XOR_WriteProcessMemory_e784 {
  strings:
    $key_e784 = { b0 f6 [2] 82 d4 [2] 84 e1 [2] aa e1 [2] 95 fd }

  condition:
    any of them
}