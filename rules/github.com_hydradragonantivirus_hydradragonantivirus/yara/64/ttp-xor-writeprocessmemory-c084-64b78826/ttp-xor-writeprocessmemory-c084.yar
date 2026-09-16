rule TTP_XOR_WriteProcessMemory_c084 {
  strings:
    $key_c084 = { 97 f6 [2] a5 d4 [2] a3 e1 [2] 8d e1 [2] b2 fd }

  condition:
    any of them
}