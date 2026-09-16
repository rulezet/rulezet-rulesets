rule TTP_XOR_WriteProcessMemory_c187 {
  strings:
    $key_c187 = { 96 f5 [2] a4 d7 [2] a2 e2 [2] 8c e2 [2] b3 fe }

  condition:
    any of them
}