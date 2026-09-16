rule TTP_XOR_WriteProcessMemory_d784 {
  strings:
    $key_d784 = { 80 f6 [2] b2 d4 [2] b4 e1 [2] 9a e1 [2] a5 fd }

  condition:
    any of them
}