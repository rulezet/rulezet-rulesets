rule TTP_XOR_WriteProcessMemory_c184 {
  strings:
    $key_c184 = { 96 f6 [2] a4 d4 [2] a2 e1 [2] 8c e1 [2] b3 fd }

  condition:
    any of them
}