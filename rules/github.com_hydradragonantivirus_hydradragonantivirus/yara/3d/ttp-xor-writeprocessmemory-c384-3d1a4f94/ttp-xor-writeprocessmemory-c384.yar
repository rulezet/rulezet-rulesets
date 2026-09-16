rule TTP_XOR_WriteProcessMemory_c384 {
  strings:
    $key_c384 = { 94 f6 [2] a6 d4 [2] a0 e1 [2] 8e e1 [2] b1 fd }

  condition:
    any of them
}