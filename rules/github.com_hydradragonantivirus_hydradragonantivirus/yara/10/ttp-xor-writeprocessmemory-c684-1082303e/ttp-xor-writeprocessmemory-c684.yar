rule TTP_XOR_WriteProcessMemory_c684 {
  strings:
    $key_c684 = { 91 f6 [2] a3 d4 [2] a5 e1 [2] 8b e1 [2] b4 fd }

  condition:
    any of them
}